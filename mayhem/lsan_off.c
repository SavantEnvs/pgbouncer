/* Disable LeakSanitizer for every fuzz and standalone binary (ASan + UBSan stay on). */
int __lsan_is_turned_off(void) { return 1; }
