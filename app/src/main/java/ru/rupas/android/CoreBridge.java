package ru.rupas.android;

import core.Core;

/**
 * W3-мост к Go-контракту: public static void core.Core.setSettings(String json).
 * Вызывается ДО Core.start; пустой/невызванный = туннель off (правила эскалируют в direct).
 *
 * Текущий app/libs/rupas-core.aar — заглушка W2 без setSettings (см. STUB_NOTICE.txt),
 * поэтому метод резолвится по контракту в рантайме: со свежим AAR от Go-воркера
 * вызов проходит напрямую, с заглушкой — говорливое исключение (tunnel остаётся off).
 */
public final class CoreBridge {

    private CoreBridge() {}

    /** @throws Exception при невалидном JSON или отсутствии метода в AAR. */
    public static void setSettings(String json) throws Exception {
        try {
            Core.class.getMethod("setSettings", String.class).invoke(null, json);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(
                    "core.Core.setSettings недоступен: AAR собран без W3-контракта", e);
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw (cause instanceof Exception) ? (Exception) cause : e;
        }
    }
}
