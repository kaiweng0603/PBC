#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    element_t g;   // generator
    element_t sk;  // secret key
    element_t pk;  // public key
} KeyPair;


// =========== 把message雜湊 =========== 
void hash_to_G1(element_t h, const char *message) {
    element_from_hash(h, (void *)message, strlen(message));
}


// ======= 讀取param並初始化pairing =======
int init_pairing_from_file(pairing_t pairing, const char *filename) {

    // 打開param檔案。
    FILE *fp = fopen(filename, "rb");
    if (!fp) return 0;

    // 讀取param檔案的長度。
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    // 把param檔案的內容存進param字串。
    char *param = malloc(fsize + 1);
    fread(param, 1, fsize, fp);
    fclose(fp);
    param[fsize] = '\0';

    // 初始化pairing參數。
    pairing_init_set_buf(pairing, param, fsize);

    // 印出param內容。
    printf("===== PARAM CONTENT =====\n");
    printf("%s", param);
    printf("=========================\n");

    free(param);

    return 1;
}


// ============ 生成公私鑰 ============
void generate_keypair(pairing_t pairing, KeyPair *key) {

    // 初始化。
    element_init_G2(key->g, pairing);   // generator
    element_init_Zr(key->sk, pairing);  // secret key
    element_init_G2(key->pk, pairing);  // public key

    element_random(key->g);     // 橢圓曲線群G2上的一個點。
    element_random(key->sk);    // Zr群中的一個常數。

    element_pow_zn(key->pk, key->g, key->sk);  // pk = g^sk; g做sk次點加法，也是橢圓曲線群G2上的一個點。
}


// =============== 簽章 ===============
void bls_sign(pairing_t pairing, const char *message, KeyPair *key, element_t sig) {

    element_t h;

    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);  // signature

    hash_to_G1(h, message);  // H(m)，雜湊過後的message，橢圓曲線群G1上的一個點。

    element_pow_zn(sig, h, key->sk);  // sig = H(m)^sk; H(m)做sk次點加法，也是橢圓曲線群G1上的一個點。

    element_clear(h);
}


// =============== 驗證 ===============
int bls_verify(pairing_t pairing, const char *message, element_t sig, KeyPair *key) {

    element_t h;
    element_t temp1;
    element_t temp2;

    // 初始化。
    element_init_G1(h, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    hash_to_G1(h, message);  // H(m)，雜湊過後的message，橢圓曲線群G1上的一個點。

    // e()把G1上的兩個點被映射到另一個群GT上，GT是有限域乘法群。
    pairing_apply(temp1, sig, key->g, pairing); // temp1 = e(sig, g)
    pairing_apply(temp2, h, key->pk, pairing);  // temp2 = e(h, pk)

    int result = !element_cmp(temp1, temp2);    // 比較temp1是否等於temp2。

    element_clear(h);
    element_clear(temp1);
    element_clear(temp2);

    return result;
}


void clear_keypair(KeyPair *key) {

    element_clear(key->g);
    element_clear(key->sk);
    element_clear(key->pk);
}


int main() {

    pairing_t pairing;

    if (!init_pairing_from_file(pairing, "param/a.param")) {
        printf("Error opening param file\n");
        return 1;
    }

    KeyPair key;
    generate_keypair(pairing, &key);

    int msg_count;

    printf("\n====================================\n");
    printf("     BLS Multiple Message System\n");
    printf("====================================\n");

    printf("請輸入訊息數量: ");
    scanf("%d", &msg_count);
    getchar();

    for (int i = 0; i < msg_count; i++) {

        char message[256];

        printf("\n------------------------------------\n");
        printf("Message %d: ", i + 1);

        fgets(message, sizeof(message), stdin);

        message[strcspn(message, "\n")] = 0;

        element_t sig;

        // Alice 簽章
        bls_sign(pairing, message, &key, sig);

        printf("\n[Alice]\n");
        printf("訊息: %s\n", message);
        printf("已成功生成簽章\n");

        // 壓縮簽章
        int compressed_size =
            pairing_length_in_bytes_compressed_G1(pairing);

        int original_size =
            pairing_length_in_bytes_G1(pairing);

        unsigned char *data =
            malloc(compressed_size);

        element_to_bytes_compressed(data, sig);

        printf("\n[Network]\n");
        printf("原始簽章大小 : %d bytes\n",
               original_size);

        printf("壓縮後大小   : %d bytes\n",
               compressed_size);

        printf("準備進行模擬傳輸...\n");

        // Bob 收到資料
        element_clear(sig);

        element_init_G1(sig, pairing);

        element_from_bytes_compressed(sig, data);

        free(data);

        printf("\n[Bob]\n");
        printf("已成功接收並還原簽章\n");

        // 驗證
        if (bls_verify(pairing,
                       message,
                       sig,
                       &key)) {

            printf("驗證成功\n");
        }
        else {

            printf("驗證失敗\n");
        }

        // 攻擊測試
        printf("\n[Attack Test]\n");

        char fake_message[256];

        strcpy(fake_message, message);

        strcat(fake_message, "_HACK");

        printf("原始訊息 : %s\n", message);
        printf("竄改訊息 : %s\n", fake_message);

        if (bls_verify(pairing,
                       fake_message,
                       sig,
                       &key)) {

            printf("攻擊成功 (不正常)\n");
        }
        else {

            printf("攻擊失敗，驗證拒絕\n");
        }

        element_clear(sig);
    }

    clear_keypair(&key);

    pairing_clear(pairing);

    return 0;
}
