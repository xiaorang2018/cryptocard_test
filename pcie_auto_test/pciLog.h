#ifndef PCI_TEST_LOG_H
#define PCI_TEST_LOG_H

void pciCunitTestWriteLog(WORD logret, WORD ret, void *reserve);
void pciCunitWriteErrLog(char *msg, char *buf, int len);

#endif

