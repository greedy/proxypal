#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <sys/prctl.h>
#include <sys/capability.h>

#include <proxy.h>

int main(int argc, char **argv)
{
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    cap_t caps = cap_get_proc();
    cap_clear(caps);
    cap_set_proc(caps);
    /* turn off output buffering */
    setbuf(stdout, NULL);

    pxProxyFactory *pf = px_proxy_factory_new();
    if (!pf) {
        return 1;
    }

    char *url = NULL;
    size_t url_capacity = 0;

    while (!feof(stdin)) {
        uint16_t msglen;
        size_t sz;

        sz = fread(&msglen, sizeof(uint16_t), 1, stdin);
        if (sz != 1) {
            return 1;
        }

        msglen = ntohs(msglen);

        if (msglen > url_capacity) {
            url = realloc(url, msglen+1);
            if (url == NULL) {
                return 1;
            }
        }

        sz = fread(url, sizeof(char), msglen, stdin);
        if (sz != msglen) {
            return 1;
        }
        url[sz] = 0;

        char **proxies = px_proxy_factory_get_proxies(pf, url);
        if (!proxies) {
            return 1;
        }

        for (char **proxyp = proxies; *proxyp; proxyp++) {
            size_t proxylen = strlen(*proxyp);
            if (proxylen >= 0xffff) {
                continue;
            }

            /* value checked in range above */
            msglen = ntohs((uint16_t) proxylen);

            sz = fwrite(&msglen, sizeof(uint16_t), 1, stdout);
            if (sz != 1) {
                return 1;
            }
            sz = fwrite(*proxyp, sizeof(char), proxylen, stdout);
            if (sz != proxylen) {
                return 1;
            }

            free(*proxyp);
        }
        msglen = 0;
        sz = fwrite(&msglen, sizeof(uint16_t), 1, stdout);
        if (sz != 1) {
            return 1;
        }
        free(proxies);
    }

    px_proxy_factory_free(pf);
    
    return 0;
}
