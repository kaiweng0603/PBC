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

    // 移動指標到檔案末尾以計算檔案大小
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
    printf("%s\n", param);
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


// =============== 執行 BLS 數位簽章 ===============
void bls_sign(pairing_t pairing, const char *message, KeyPair *key, element_t sig) {

    element_t h;

    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);  // signature

    hash_to_G1(h, message);  // H(m)，雜湊過後的message，橢圓曲線群G1上的一個點。

    element_pow_zn(sig, h, key->sk);  // sig = H(m)^sk; H(m)做sk次點加法，也是橢圓曲線群G1上的一個點。

    element_clear(h);
}


// =============== 執行單人簽章驗證 ===============
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

// ============ 釋放金鑰結構體的記憶體 ============
void clear_keypair(KeyPair *key) {
    element_clear(key->g);
    element_clear(key->sk);
    element_clear(key->pk);
}

// =============== BLS 聚合簽章展示 (不同訊息方案) ===============
void aggregate_demo(pairing_t pairing){
    #define USER_COUNT 3 //模擬3位使用者

    KeyPair users[USER_COUNT];
    // 模擬 3 位使用者各自想要簽署的不同訊息內容
    char *messages[USER_COUNT] = {
        "Hello",
        "World",
        "BLS"
    };

    printf("\n====================================\n");
    printf("      Aggregate Signature Demo\n");
    printf("====================================\n");

    // 生成第 1 位使用者的金鑰，作為基準點
    generate_keypair(pairing,&users[0]);

    // 生成其餘使用者的金鑰，並將他們的基點 g 同步對齊
    for(int i=1;i<USER_COUNT;i++){
        generate_keypair(pairing,&users[i]);

        // 多人聚合必須共用同一個基點 g，因此強制複製 users[0].g
        element_set(users[i].g,users[0].g);

        // 基點改變後，必須重新用各自的私鑰計算出對應的公鑰 pk = g^sk
        element_pow_zn(users[i].pk,users[i].g,users[i].sk);
    }

    element_t agg_sig;

    element_init_G1(agg_sig,pairing);

    element_set1(agg_sig); // 初始化：將聚合簽章設為群的單位元（乘法群的 1）

    // --- 簽章與聚合階段 ---
    for(int i=0;i<USER_COUNT;i++){
        element_t sig;

        // 每位使用者用自己的私鑰，對各自的訊息進行標準 BLS 簽章
        bls_sign(pairing,messages[i],&users[i],sig);

        printf("\nUser %d\n",i + 1);
        printf("Message : %s\n",messages[i]);
        
        // 核心聚合公式：agg_sig = ∏ sig_i。
        element_mul(agg_sig,agg_sig,sig);

        element_clear(sig);
    }

    // --- 聚合驗證階段 (由驗證端執行) ---
    element_t left;
    element_t right;

    element_init_GT(left,pairing);
    element_init_GT(right,pairing);

    // 計算驗證左式：e(agg_sig, g)。只需做「1次」雙線性對運算
    pairing_apply(left,agg_sig,users[0].g,pairing);

    // 初始化驗證右式連乘積為 1
    element_set1(right);

    // 計算驗證右式：∏ e(H(m_i), PK_i)。
    // 因為每個人簽的訊息不同，驗證端必須分別計算每個訊息的雜湊與公鑰配對，再全部乘起來。
    for(int i=0;i<USER_COUNT;i++){
        element_t h;
        element_t temp;

        element_init_G1(h,pairing);
        element_init_GT(temp,pairing);

        hash_to_G1(h,messages[i]);                  // 計算 H(m_i)
        pairing_apply(temp,h,users[i].pk,pairing);  // 計算 e(H(m_i), PK_i)
        element_mul(right,right,temp);              // 右式累乘：right = right * temp

        element_clear(h);
        element_clear(temp);
    }

    printf("\n");
    // 若 e(∏ sig_i, g) == ∏ e(H(m_i), PK_i)，則代表這 3 個簽章皆合法
    if(!element_cmp(left,right))
        printf("Aggregate Verify Success\n");
    else
        printf("Aggregate Verify Failed\n");

    element_clear(left);
    element_clear(right);
    element_clear(agg_sig);

    for(int i=0;i<USER_COUNT;i++){
        clear_keypair(&users[i]);
    }
}

// ============ 選單與單人簽章流程 ============
int main() {
    int choice;

    pairing_t pairing;
    // 初始化 pairing 矩陣
    if (!init_pairing_from_file(pairing, "param/g149.param")){
        printf("Error opening param file\n");
        return 1;
    }

    // 列印功能選擇選單
    printf("\n");
    printf("1. Single Signature Demo (with Compression)\n");
    printf("2. Aggregate Signature Demo\n");
    printf("\nChoose: ");
    scanf("%d",&choice);
    getchar();

    // 若使用者選擇 2，進入聚合簽章展示
    if(choice == 2){
        aggregate_demo(pairing);
        pairing_clear(pairing);
        return 0;
    }

    // --- 單人簽章流程（含點壓縮傳輸與破壞測試） ---
    KeyPair key;
    generate_keypair(pairing,&key);
    char message[256];

    printf("\n====================================\n");
    printf("      BLS Signature System V1\n");
    printf("====================================\n");

    printf("請輸入訊息: ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = 0;

    // Alice 執行簽章
    element_t sig;
    bls_sign(pairing, message, &key, sig);

    printf("\n[Alice]\n");
    printf("訊息: %s\n", message);

    element_printf("\nPublic Key:\n%B\n", key.pk);
    element_printf("\nSignature:\n%B\n", sig);

    // --- 模擬真實網路傳輸 ---
    int original_size = pairing_length_in_bytes_G1(pairing);                // 取得原始未壓縮點大小
    int compressed_size = pairing_length_in_bytes_compressed_G1(pairing);   // 取得點壓縮後大小
    unsigned char *data = malloc(compressed_size);                          // 動態配置壓縮後的簽章存儲空間
    element_to_bytes_compressed(data, sig);

    printf("\n[Network]\n");
    printf("原始簽章大小 : %d bytes\n",original_size);
    printf("壓縮後大小 : %d bytes\n",compressed_size);
    printf("節省空間 : %.2f%%\n",100.0 *(original_size - compressed_size) / original_size);

    // --- 模擬接收端 Bob ---
    element_clear(sig);
    element_init_G1(sig, pairing);

    // Bob 從網路上收到的 data 陣列中，重新還原並解壓縮出簽章點
    element_from_bytes_compressed(sig, data);
    free(data);

    printf("\n[Bob]\n");
    printf("已成功接收並還原簽章\n");

    // 進行簽章合法性驗證
    if (bls_verify(pairing,message,sig,&key)) 
        printf("驗證成功\n");
    else 
        printf("驗證失敗\n");

    // --- 黑客篡改攻擊測試 ---
    printf("\n===== Attack Test =====\n");

    char fake_message[300]; // 加大容量，預留空間給 _HACK

    strcpy(fake_message, message);
    strcat(fake_message, "_HACK");
    printf("原始訊息 : %s\n",message);
    printf("竄改訊息 : %s\n",fake_message); // 在原始訊息後方強行加上惡意篡改字串

    // 用被篡改過的髒訊息再次丟入驗證函式
    if (bls_verify(pairing,fake_message,sig,&key))
        printf("攻擊成功 (異常)\n");
    else
        printf("攻擊失敗，驗證拒絕\n");

    element_clear(sig);
    clear_keypair(&key);
    pairing_clear(pairing);

    return 0;
}

