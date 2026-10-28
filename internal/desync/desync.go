// Package desync компилирует desync-профиль провайдера (config.DesyncParams)
// в детерминированный список операций над сегментами ClientHello — контракт
// из SYSTEM_DESIGN.md §3.2/§5 для ветки DESYNC в capture.
//
// Горячий путь свободен от аллокаций: операции запакованы в интерфейсы Op
// один раз в New, а Actions переиспользует внутренний слайс фиксированной
// ёмкости (назначенной в New и не растущей между вызовами сверх
// max(1, Repeats); исключение — двухоперационные стратегии при Repeats == 1).
package desync

import (
	"fmt"

	"github.com/kshishtovsky/rupas/internal/config"
)

// Op — закрытое множество операций desync. Ядро capture исполняет их над
// потоком после инспекции ClientHello; последовательность фиксирована.
type Op interface {
	isOp()
}

// InjectFake — инжект Count фейковых ClientHello (payload = Engine.Template)
// с TTL меньше числа хопов до TSPU: фейки снимаются транзитным узлом, DPI
// строит сессию по фейку, оригинал доходит до сервера (PRD §2, лаборатория).
// seq/ack и checksums вычисляет ядро capture из состояния потока.
type InjectFake struct {
	// TTL фейк-пакетов: калиброванное prober'ом значение + margin.
	TTL uint8
	// Count — число инжектов на один handshake (= Repeats профиля).
	Count int
}

// isOp реализует закрытый интерфейс Op.
func (InjectFake) isOp() {}

// SplitAt — разрез реального ClientHello по смещению Offset байт: сегмент
// уходит двумя (или более) пакетами, и DPI не восстанавливает CH целиком.
type SplitAt struct {
	Offset uint32
}

// isOp реализует закрытый интерфейс Op.
func (SplitAt) isOp() {}

var (
	_ Op = InjectFake{}
	_ Op = SplitAt{}
)

// Engine — скомпилированный desync-профиль. Неизменяем после New; Actions
// детерминирован. В v1 операции не зависят от SNI (параметр Actions
// зарезервирован под per-SNI стратегии v2). Engine не goroutine-safe:
// по SYSTEM_DESIGN §3.2 capture-слой однопоточен, fan-out запрещён.
type Engine struct {
	useFake  bool
	useSplit bool
	fakeOp   Op // запакованы один раз в New — Actions не boxing'ит значения
	splitOp  Op

	// ops переиспользуется между вызовами Actions; ёмкость назначена в New
	// и в рантайме не растёт (нулевые аллокации на вызов).
	ops []Op

	template []byte // фейковый ClientHello; Template() отдаёт его без копии
}

// New валидирует профиль и fake-шаблон, компилирует Engine.
//
// Стратегии профиля (Strategy):
//
//	fake               → [InjectFake]
//	fake,split         → [InjectFake, SplitAt]  (alias: fake_split из config)
//	multisplit         → [InjectFake, SplitAt]
//	split              → [SplitAt]
//	disorder, disorder2 → [SplitAt] — v1-аппроксимация, см. TODO в switch
//
// Валидация: стратегия из списка выше; TTL ∈ [1,32]; TTLMargin ≥ 0 и
// TTL+TTLMargin ≤ 255; Repeats ∈ [1,16]; SplitOffset ≥ 0 для split-стратегий;
// шаблон непустой и начинается с TLS handshake record (0x16 0x03).
func New(profile config.DesyncParams, fakeTemplate []byte) (*Engine, error) {
	e := &Engine{}
	switch profile.Strategy {
	case "fake":
		e.useFake = true
	case "fake,split", "fake_split": // fake_split — форма из config.DesyncStrategies()
		e.useFake, e.useSplit = true, true
	case "multisplit":
		e.useFake, e.useSplit = true, true
	case "split":
		e.useSplit = true
	case "disorder", "disorder2":
		// TODO(reorder): настоящая disorder-механика — перестановка сегментов
		// CH в sequence-space (Reorder{Permutation}) — требует очереди
		// отправки на уровне capture (порядок WinDivertSend). В v1
		// аппроксимируем её split-ом по profile.SplitOffset.
		e.useSplit = true
	default:
		return nil, fmt.Errorf("desync: unknown strategy %q (want one of fake, fake,split, multisplit, split, disorder, disorder2)",
			profile.Strategy)
	}
	if profile.TTL < 1 || profile.TTL > 32 {
		return nil, fmt.Errorf("desync: ttl %d out of range [1,32]", profile.TTL)
	}
	if profile.TTLMargin < 0 {
		return nil, fmt.Errorf("desync: ttl_margin %d is negative", profile.TTLMargin)
	}
	if sum := profile.TTL + profile.TTLMargin; sum > 255 {
		return nil, fmt.Errorf("desync: ttl %d + ttl_margin %d = %d overflows uint8",
			profile.TTL, profile.TTLMargin, sum)
	}
	if profile.Repeats < 1 || profile.Repeats > 16 {
		return nil, fmt.Errorf("desync: repeats %d out of range [1,16]", profile.Repeats)
	}
	if e.useSplit && profile.SplitOffset < 0 {
		return nil, fmt.Errorf("desync: split_offset %d is negative", profile.SplitOffset)
	}
	if err := checkTemplate(fakeTemplate); err != nil {
		return nil, fmt.Errorf("desync: %w", err)
	}
	e.template = fakeTemplate
	if e.useFake {
		e.fakeOp = InjectFake{TTL: uint8(profile.TTL + profile.TTLMargin), Count: profile.Repeats}
	}
	if e.useSplit {
		e.splitOp = SplitAt{Offset: uint32(profile.SplitOffset)}
	}
	n := 0
	if e.useFake {
		n++
	}
	if e.useSplit {
		n++
	}
	// Ёмкость: достаточно для всех операций стратегии, но не меньше
	// max(1, Repeats) — слайс никогда не растёт в Actions.
	e.ops = make([]Op, 0, max(n, profile.Repeats))
	if e.useFake {
		e.ops = append(e.ops, e.fakeOp)
	}
	if e.useSplit {
		e.ops = append(e.ops, e.splitOp)
	}
	return e, nil
}

// Actions возвращает операции стратегии для потока с данным SNI. Вызов не
// аллоцирует: Op-значения запакованы в New, слайс ops фиксированной ёмкости
// переиспользуется. Результат не сохранять между вызовами (общий слайс).
// sni в v1 не влияет на набор операций; параметр оставлен контрактом
// capture-слоя под per-SNI стратегии v2.
func (e *Engine) Actions(sni []byte) []Op {
	ops := e.ops[:0]
	if e.useFake {
		ops = append(ops, e.fakeOp)
	}
	if e.useSplit {
		ops = append(ops, e.splitOp)
	}
	e.ops = ops
	return ops
}

// Template возвращает payload фейкового ClientHello — тот же слайс, что был
// передан в New (без копии; вызывающий код не должен его модифицировать).
func (e *Engine) Template() []byte {
	return e.template
}
