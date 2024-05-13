# WBCrypto 白盒密码学库 整体约定

这里是本密码学库的“整体API风格”，了解这些可以帮助你更好地了解API的用法。

本密码学库的整体约定与mbedtls相似，可以参考[MBedtls 编码规范](https://tls.mbed.org/kb/development/mbedtls-coding-standards)的API conventions部分。

## 函数

### 命名

函数名称格式为：wbcrypto_%模块名%_%具体函数名%()
</br>例如：wbcrypto_wbsm2_encrypt 即为WBSM2模块下的加密函数

### 返回值与错误码

#### 返回值

除\return特别说明外，一般以返回0为成功，其它值为失败。

#### 错误码

由于mbedtls早已用尽了其错误码空间，wbcrypto必须扩大错误码空间才有位置用。
</br>wbcrypto的错误码长度为32bit，而高16bit全部为1，第17bit为0。
</br>这样wbcrypto在32bit的机器上将会占据32bit空间里的负数部分。最坏情况在16bit的机器上将占据mbedtls没有使用的正数部分。
</br>具体的错误码分配请参考头文件error.h

## 结构体

### Session类结构体

库中有一些特殊的结构体，其名字以session结尾（例如wbcrypto_wbsm2_decrypt_session）。这些结构体多用于存储处理单个请求的中间状态，当某次调用失败（例如调用wbcrypto_wbsm2_decrypt_stepA失败）后一般必须free掉。

其它结构体（例如wbcrypto_wbsm2_public_key）多用于存储某种算法需要的数据与预计算值，当某次功能调用失败（例如调用wbcrypto_wbsm2_decrypt_client_complete失败）后一般可以继续使用。

上述行为会在具体的API头文件中以\note进行额外标注，但大致如上

### 生命周期方法

结构体一般在使用前都需要初始化，在使用完后需要释放。
如果某个结构体需要初始化/释放，则做这些事情的函数签名规律如下：
* 初始化函数： void %结构体名称%_init(%结构体名称%* ctx);
    * 例如 void wbcrypto_wbsm2_public_key_init(wbcrypto_wbsm2_public_key* key);
* 释放函数：   void %结构体名称%_free(%结构体名称%* ctx);

如果该结构体要进行一些可能会产生错误的初始化行为，那么将会有一个额外的函数干这些事情，必须在使用前，调用init后调用它：
* 第二步初始化函数：int %结构体名称%_setup(%结构体名称%* ctx);

如果没有相关的函数定义，就不需要进行相关流程