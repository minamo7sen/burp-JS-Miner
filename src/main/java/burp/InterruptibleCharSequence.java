package burp;

/**
 * {@link CharSequence} that notices {@link Thread} interrupts
 *
 * @author gojomo - http://stackoverflow.com/questions/910740/cancelling-a-long-running-regex-match
 */
class InterruptibleCharSequence implements CharSequence {
    CharSequence inner;

    public InterruptibleCharSequence(CharSequence inner) {
        super();
        this.inner = inner;
    }

    @Override
    public char charAt(int index) {
        if (Thread.currentThread().isInterrupted()) {
            throw new RuntimeException("Interrupted!");
        }
        return inner.charAt(index);
    }

    @Override
    public int length() {
        return inner.length();
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return new InterruptibleCharSequence(inner.subSequence(start, end));
    }

    @Override
    public String toString() {
        return inner.toString();
    }
}