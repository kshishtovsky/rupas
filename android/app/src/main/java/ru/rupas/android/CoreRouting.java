package ru.rupas.android;

import core.Core;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Адаптер к методам ядра из контракта T1 (docs/ROUTING_UI.md §10):
 * RulesJSON() string, SetRulesJSON(string) error, TestRoute(string) string.
 *
 * Собранный AAR может быть старше контракта, поэтому вызовы идут рефлексией
 * (тот же приём, что CoreBridge.setSettings): нет метода — экран говорит
 * «проверка недоступна» / показывает ошибку, но не падает.
 */
final class CoreRouting {

    private CoreRouting() {
    }

    private static Method lookup(String name, Class<?>... args) {
        try {
            return Core.class.getMethod(name, args);
        } catch (Throwable t) {
            return null;
        }
    }

    static boolean hasSetRules() {
        return lookup("setRulesJSON", String.class) != null;
    }

    static boolean hasTestRoute() {
        return lookup("testRoute", String.class) != null;
    }

    /** @throws Exception текст ошибки движка как есть. */
    static String rulesJson() throws Exception {
        Method m = lookup("rulesJSON");
        if (m == null) {
            throw new IllegalStateException(
                    "ядро не отдаёт правила: core.Core.RulesJSON отсутствует в AAR");
        }
        return (String) call(m);
    }

    /** Правила применяются при следующем Start (текущая семантика ядра). */
    static void setRulesJson(String json) throws Exception {
        Method m = lookup("setRulesJSON", String.class);
        if (m == null) {
            throw new IllegalStateException(
                    "ядро не принимает правила: core.Core.SetRulesJSON отсутствует в AAR");
        }
        call(m, json);
    }

    /** JSON трассы: {stage,stageName,matcher,action,note}. */
    static String testRoute(String query) throws Exception {
        Method m = lookup("testRoute", String.class);
        if (m == null) {
            throw new IllegalStateException(
                    "ядро не умеет проверять маршрут: core.Core.TestRoute отсутствует в AAR");
        }
        return (String) call(m, query);
    }

    private static Object call(Method m, Object... args) throws Exception {
        try {
            return m.invoke(null, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw (cause instanceof Exception) ? (Exception) cause : e;
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("метод ядра недоступен: " + m.getName(), e);
        }
    }
}
