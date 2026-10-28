package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// Регресс «отправка медиа виснет на середине»: упавший packet-up POST
// раньше только записывал ошибку, и поток продолжал отдавать ACK'и за байты,
// которые уже не дошли. Если отправка в этот момент стояла (Telegram ждёт
// своего подтверждения), следующего Write не было — поток висел, а не рвался.
// Теперь ошибка POST немедленно закрывает соединение.
func TestXHTTPPostFailureClosesStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &xhttpConn{
		sctx:   ctx,
		cancel: cancel,
		sem:    make(chan struct{}, 8),
	}
	closed := make(chan struct{})
	c.closedCh = closed // тестовый хук вместо Close()

	c.setWriteErr(errors.New("post failed"))

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("поток не закрылся после ошибки POST — зависание вернётся")
	}
	if got := c.postFailN.Load(); got != 1 {
		t.Fatalf("postFailN = %d, ждали 1", got)
	}
	// Повторная ошибка не должна закрывать поток второй раз и не должна
	// перетирать первую причину.
	c.setWriteErr(errors.New("second"))
	if c.writeErr.Error() != "post failed" {
		t.Fatalf("причина перетёрта: %v", c.writeErr)
	}
	if got := c.postFailN.Load(); got != 1 {
		t.Fatalf("postFailN = %d после второй ошибки, ждали 1", got)
	}
}

// Write обязан вернуть ошибку сразу после провала POST, а не пытаться
// отправить ещё: иначе клиент получит ACK за заведомо потерянные байты.
func TestXHTTPWriteFailsFastAfterPostError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &xhttpConn{sctx: ctx, cancel: cancel, sem: make(chan struct{}, 8)}
	c.setWriteErr(net.ErrClosed)

	if _, err := c.Write([]byte("hello")); err == nil {
		t.Fatal("Write после ошибки POST вернул nil")
	}
}

// Регресс «отправка замирает через миг после старта»: dial-ctx отменяется
// вызывающим сразу после Connect (tcpterm: defer cancel(); probe: dcancel()).
// Если контекст потока наследует эту отмену, все последующие POST/GET
// мгновенно падают, и поток молча умирает посреди передачи.
func TestStreamContextSurvivesDialCancel(t *testing.T) {
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)

	sctx, scancel := streamContext(dialCtx)
	defer scancel()

	cancelDial() // так делает и tcpterm, и probe после установления потока
	time.Sleep(20 * time.Millisecond)

	select {
	case <-sctx.Done():
		t.Fatal("контекст потока умер вместе с dial-ctx — передача оборвётся на старте")
	default:
	}

	// Свой cancel обязан работать: иначе поток никогда не закроется.
	scancel()
	select {
	case <-sctx.Done():
	case <-time.After(time.Second):
		t.Fatal("scancel не отменил контекст потока")
	}
}
