int runcontract(int x) {
        int i = 0;
        while (i < 8) {
                x = x + x;
                i = i + 1;
        }

        return x;
}
