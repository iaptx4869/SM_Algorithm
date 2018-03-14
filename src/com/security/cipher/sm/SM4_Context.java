package com.security.cipher.sm;

class SM4_Context {
    public final long[] sk;
    public int mode;
    public boolean isPadding;

    public SM4_Context() {
        this.mode = 1;
        this.isPadding = true;
        this.sk = new long[32];
    }
}
