package ru.rupas.android;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;
import android.animation.ValueAnimator;

/**
 * Кольцо вокруг клавиши питания: дуга «подключаюсь» и замкнутый контур «защищено».
 * Существует потому, что статус из сервиса приходит с задержкой в секунды, а нажатие
 * обязано отзываться мгновенно — кольцо стартует по кнопке, а не по опросу.
 */
public final class PowerRingView extends View {

    public static final int IDLE = 0;
    public static final int BUSY = 1;
    public static final int ACTIVE = 2;

    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private int mode = IDLE;
    private float spin;
    private float reveal;
    private ValueAnimator spinAnim;
    private ValueAnimator revealAnim;

    public PowerRingView(Context context, AttributeSet attrs) {
        super(context, attrs);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeCap(Paint.Cap.ROUND);
        paint.setStrokeWidth(3f * getResources().getDisplayMetrics().density);
    }

    /** @param next IDLE — кольца нет, BUSY — бегущая дуга, ACTIVE — замкнутый контур. */
    public void setMode(int next) {
        if (next == mode) return;
        mode = next;
        stopSpin();
        if (next == BUSY) {
            paint.setColor(getContext().getColor(R.color.warn));
            startSpin();
            animateReveal(0.25f, 220);
        } else {
            paint.setColor(getContext().getColor(R.color.accent));
            animateReveal(next == ACTIVE ? 1f : 0f, next == ACTIVE ? 460 : 220);
        }
    }

    private void animateReveal(float to, long ms) {
        if (revealAnim != null) revealAnim.cancel();
        revealAnim = ValueAnimator.ofFloat(reveal, to).setDuration(ms);
        revealAnim.setInterpolator(new DecelerateInterpolator());
        revealAnim.addUpdateListener(a -> {
            reveal = (float) a.getAnimatedValue();
            invalidate();
        });
        revealAnim.start();
    }

    private void startSpin() {
        spinAnim = ValueAnimator.ofFloat(0f, 360f).setDuration(1000);
        spinAnim.setRepeatCount(ValueAnimator.INFINITE);
        spinAnim.setInterpolator(new LinearInterpolator());
        spinAnim.addUpdateListener(a -> {
            spin = (float) a.getAnimatedValue();
            invalidate();
        });
        spinAnim.start();
    }

    private void stopSpin() {
        if (spinAnim != null) {
            spinAnim.cancel();
            spinAnim = null;
        }
    }

    @Override
    protected void onDraw(Canvas canvas) {
        if (reveal <= 0f) return;
        float half = Math.min(getWidth(), getHeight()) / 2f;
        float r = half - paint.getStrokeWidth();
        canvas.drawArc(half - r, half - r, half + r, half + r,
                mode == BUSY ? spin - 90f : -90f, 360f * reveal, false, paint);
    }

    @Override
    protected void onDetachedFromWindow() {
        stopSpin();
        if (revealAnim != null) revealAnim.cancel();
        super.onDetachedFromWindow();
    }
}
