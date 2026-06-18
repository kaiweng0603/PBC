#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void hash_to_G1(element_t h, const char *message) {
    element_from_hash(h, message, strlen(message));
}

int main() {
    
    //打開param檔案，檔案路徑可改。
    FILE *fp = fopen("../pbc-1.0.0/param/a.param", "rb");
    if (!fp) {
        printf("Error opening param file\n");
        return 1;
    }

    //讀取param檔案的長度。
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    //把param檔案的內容存進param字串。
    char *param = malloc(fsize + 1);
    fread(param, 1, fsize, fp);
    fclose(fp);
    param[fsize] = '\0';

    //初始化pairing參數。
    pairing_t pairing;
    pairing_init_set_buf(pairing, param, fsize);

    //印出param內容。
    printf("===== PARAM CONTENT =====\n");
    printf("%s", param);
    printf("=========================\n");
    
    free(param);

    // ======= 生成公私鑰 =======
    element_t g, sk, pk;
    element_init_G1(g, pairing);    //g = generator。 橢圓曲線群G1上的一個點。
    element_init_Zr(sk, pairing);   //sk = secret key。 Zr群中的一個常數。
    element_init_G1(pk, pairing);   //pk = private key。

    element_random(g);
    element_random(sk);
    element_pow_zn(pk, g, sk);      //pk = g^sk; g做sk次點加法，也是橢圓曲線群G1上的一個點。

    // ========== 訊息 ==========
    char *message = "Hello BLS Signature!";

    // ========== 簽章 ==========
    element_t h, sig;
    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);  //sig = signature 

    hash_to_G1(h, message);         //H(m)，雜湊過後的message，橢圓曲線群G1上的一個點。 
    element_pow_zn(sig, h, sk);     //sig = H(m)^sk; H(m)做sk次點加法，也是橢圓曲線群G1上的一個點。

    // ========== 驗證 ==========
    element_t left, right;
    element_init_GT(left, pairing);
    element_init_GT(right, pairing);

    //e()把G1上的兩個點被映射到另一個群GT上，GT是有限域乘法群。
    pairing_apply(left, sig, g, pairing);   //left = e(sig, g);
    pairing_apply(right, h, pk, pairing);   //right = e(h, pk)

    //輸出結果。
    if (!element_cmp(left, right)) {
        printf("驗證成功\n");
    } else {
        printf("驗證失敗\n");
    }
    
    return 0;
}
