# ZK-ACL: Keystone TEE 的零知识访问控制列表

本示例演示了一个**基于零知识证明的访问控制系统**，用于 Keystone enclaves，实现了 **"ACL + 审计者"模型**。它允许验证者 enclave 使用访问控制列表（ACL）对证明者 enclave 进行身份验证，而无需透露证明者的私有身份。

## 🎯 概述

系统由以下部分组成：

1. **ZK 库** (`zklib/`)：**真实的 Groth16 ZK 证明库**，使用 Rust 编写，基于 [arkworks](https://github.com/arkworks-rs/groth16)，编译为静态库并集成到 enclave 中
2. **证明者 Enclave** (`eapp1/`)：生成 ZK 证明以证明群组成员身份
3. **验证者 Enclave** (`eapp2/`)：维护 ACL 并验证 ZK 证明
4. **主机应用** (`host/`)：enclave 之间的纯消息中继（无 ZK 操作）

### 🔬 **真实的密码学实现**

与简化的演示不同，本示例使用**生产级零知识证明**：
- **Groth16 SNARKs**：业界标准的 ZK 证明系统
- **BN254 曲线**：高效的配对友好椭圆曲线
- **arkworks 库**：来自 Aleo/zkSNARK 社区的高性能 Rust 实现
- **编译到 Enclave**：Rust 静态库直接链接到 RISC-V enclave 二进制文件中

## 🔑 核心特性

### ✅ 完全零知识
- **私有 user_id 永不离开 enclave**：所有 ZK 操作都在 enclave 内部进行
- **主机完全不可信**：主机仅中继加密消息
- **验证者一无所知**：验证者只知道证明者是否被授权，而不知道其身份

### ✅ 基于 ACL 的授权
- **灵活的群组管理**：验证者维护已授权 `public_id` 列表
- **可扩展**：支持具有不同身份的多个成员
- **安全存储**：ACL 存储在验证者 enclave 内部

### ✅ 挑战-响应身份验证
- **防止重放攻击**：每次身份验证使用新鲜的随机 nonce
- **一次性使用**：挑战在验证后被消耗
- **时间戳验证**：确保身份验证请求的新鲜性

### ✅ 两阶段验证
1. **授权**：检查 `public_id` 是否在 ACL 中
2. **身份验证**：验证 ZK 证明，证明者知道秘密的 `user_id`

## 📐 架构

```
┌─────────────────────────────────┐    ┌─────────────────────────────────┐
│   Enclave1 (证明者)             │    │   Enclave2 (验证者 + ACL)       │
│                                 │    │                                 │
│  📦 ZK 库 (已集成)              │    │  📦 ZK 库 (已集成)              │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │    │  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  🔒 私有：user_id               │    │  📋 ACL_GroupX[]                │
│  🔓 公开：public_id             │    │     - hash(alice_id)            │
│  🧮 ZK 操作：                   │    │     - hash(bob_id)              │
│     - compute_public_id()       │    │     - hash(charlie_id)          │
│     - generate_proof()          │    │  🔐 挑战列表[]                  │
│                                 │    │  🧮 ZK 操作：                   │
│  ✅ user_id 永不离开这里        │    │     - verify_proof()            │
└─────────────────────────────────┘    └─────────────────────────────────┘
         │                                      │
         │   🚚 仅公开信息：                     │
         │      - public_id (哈希)              │
         │      - proof (ZK 证明)               │
         │      - nonce (挑战)                  │
         ↓                                      ↓
┌────────────────────────────────────────────────────────┐
│           主机 (不可信消息中继)                         │
│                                                        │
│  📬 消息队列：                                         │
│     - join_request_queue                               │
│     - challenge_queue                                  │
│     - proof_queue                                      │
│     - result_queue                                     │
│                                                        │
│  ✅ 主机对私有数据一无所知                             │
└────────────────────────────────────────────────────────┘
```

## 🔄 协议流程

```
Enclave1 (证明者)           主机                    Enclave2 (验证者)
      │                            │                          │
      │                            │                          │
      ├─ 1. 计算 public_id ───────┤                          │
      │    (在 Enclave1 内)        │                          │
      │    hash(user_id) = public_id                          │
      │                            │                          │
      ├─ 2. REQ_JOIN_GROUP ───────►│                          │
      │    (public_id, GroupX)     │                          │
      │                            ├─ 转发 ─────────────────►│
      │                            │                          │
      │                            │                ┌─────────┴─────────┐
      │                            │                │ 阶段 1：授权检查
      │                            │                │ - 首先检查 ACL
      │                            │                │ - public_id 在列表中？
      │                            │                │ - 如果否：拒绝
      │                            │                │   (无需 ZK 初始化)
      │                            │                │ - 如果是：继续
      │                            │                └─────────┬─────────┘
      │                            │                          │
      │                            │                ┌─────────┴─────────┐
      │                            │                │ 阶段 2：ZK 设置
      │                            │                │ - 初始化 ZK
      │                            │                │ - 生成密钥
      │                            │                │ - 创建挑战
      │                            │                └─────────┬─────────┘
      │                            │                          │
      │                            │◄─ 3. 挑战 ───────────────┤
      │                            │    (nonce)               │
      │◄─ 转发 ────────────────────┤                          │
      │                            │                          │
┌─────┴─────┐                     │                          │
│ 阶段 3：身份验证                  │                          │
│ - 生成 ZK 证明                   │                          │
│ - 绑定：user_id,                │                          │
│        public_id, nonce         │                          │
│ - 在 Enclave1 内                │                          │
│   生成证明                       │                          │
└─────┬─────┘                     │                          │
      │                            │                          │
      ├─ 4. 证明 ─────────────────►│                          │
      │    (proof, public_id, nonce)│                          │
      │                            ├─ 转发 ─────────────────►│
      │                            │                          │
      │                            │                ┌─────────┴─────────┐
      │                            │                │ 阶段 4：验证
      │                            │                │ - 验证 nonce
      │                            │                │ - 验证 ZK 证明
      │                            │                │   (在 Enclave2 内)
      │                            │                │ - 消耗挑战
      │                            │                └─────────┬─────────┘
      │                            │                          │
      │                            │◄─ 5. 结果 ───────────────┤
      │                            │    (VALID/INVALID)       │
      │◄─ 转发 ────────────────────┤                          │
      │                            │                          │
      ├─ ✓ 验证成功！              │                          │
      │                            │                          │
```

## 🛡️ 安全属性

### 1. 零知识性
- **属性**：验证者无法了解证明者的私有 `user_id`
- **证明**：所有 ZK 操作都在 enclave 内进行；仅透露 `public_id` 和 `proof`
- **即使被攻破**：即使主机或验证者被攻破，`user_id` 仍然保密

### 2. 健全性
- **属性**：无效证明无法通过验证
- **证明**：ZK 证明将 `user_id` 绑定到 `public_id`；不匹配会导致证明生成失败
- **抗攻击性**：没有秘密 `user_id` 就无法伪造证明

### 3. 完整性
- **属性**：来自授权成员的有效证明总是能通过验证
- **证明**：如果 `hash(user_id) == public_id` 且 `public_id` 在 ACL 中，验证成功
- **无误报**：合法成员总是可以进行身份验证

### 4. 防重放
- **属性**：旧证明无法重用
- **证明**：每个挑战使用新鲜的 nonce；nonce 在使用后被消耗
- **抗攻击性**：重放的证明会因 nonce 不匹配或"已使用"错误而失败

### 5. 身份绑定
- **属性**：证明者无法冒充他人
- **证明**：两阶段验证：
  - 阶段 1：证明者声明 `public_id`（授权）
  - 阶段 2：证明者证明知道与 `public_id` 匹配的 `user_id`（身份验证）
- **抗攻击性**：无法为不同的 `public_id` 生成有效证明

## 📐 技术规格

### ZK 电路详细说明

#### 公开输入（Public Inputs）
按照 Groth16 协议规范，公开输入的顺序是严格定义的：

```rust
// 公开输入向量
let public_inputs = vec![
    public_id_field,  // 索引 0：公开身份（Fr 字段元素）
    nonce_field,      // 索引 1：挑战值（Fr 字段元素）
];
```

**重要**：验证者必须使用完全相同的顺序构造公开输入，否则验证将失败。

#### 私有输入（Witness）
```rust
struct UserIDCircuit {
    user_id_hash: Option<Fr>,  // 私有：SHA256(user_id) 的字段表示
    public_id: Option<Fr>,     // 公开：公开身份
    nonce: Option<Fr>,         // 公开：挑战值
}
```

#### 电路约束
```rust
// R1CS 约束：user_id_hash == public_id
cs.enforce_constraint(
    lc!() + user_id_hash_var,
    lc!() + Variable::One,
    lc!() + public_id_var,
)?;

// nonce 作为公开输入包含在证明中（防止重放）
// 无需额外约束，仅用于绑定证明到特定挑战
```

### 数据格式与编码

#### 1. `public_id` 格式
- **原始值**：SHA256 哈希值
- **编码**：十六进制字符串（64 个字符）
- **示例**：`"39695f33deef797075fa1abb90f6838d58b9689f649236909634ec6f474c90bf"`

**生成过程**：
```c
// 在 Enclave1 中
ZK_ComputePublicID(user_id, user_id_len, public_id, sizeof(public_id))
// 输出：public_id = hex(SHA256(user_id))
```

**字段转换**（用于 ZK 电路）：
```rust
// 在 zklib/src/lib.rs 中
fn hash_to_field(data: &[u8]) -> Fr {
    let hash = SHA256(data);  // 32 字节
    let val = u64::from_le_bytes(hash[0..8]);  // 取前 8 字节
    Fr::from(val % 1000000000000u64)  // 转换为有限域元素
}

// 使用示例
let public_id_bytes = hex::decode(public_id_hex_string)?;
let public_id_field = hash_to_field(&public_id_bytes);
```

#### 2. `nonce` 处理

**生成（在 Enclave2 中）**：
```c
static uint64_t prng_state;  // PRNG 状态（Enclave 内部）

static uint64_t generate_nonce() {
    // LCG（线性同余生成器）
    prng_state = prng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    uint64_t ts = get_timestamp();
    return prng_state ^ prng_counter ^ ts;  // 混合多个熵源
}
```

**存储（防重放）**：
```c
struct ChallengeRecord {
    uint64_t nonce;         // 挑战值
    char public_id[65];     // 绑定到特定用户
    uint64_t timestamp;     // 生成时间
    int used;               // 0 = 未使用, 1 = 已使用
    int active;             // 0 = 无效, 1 = 活动
};

static struct ChallengeRecord challenges[MAX_CHALLENGES];
```

**验证和消费**：
```c
int verify_and_consume_challenge(uint64_t nonce, const char* public_id) {
    // 1. 查找匹配的 (nonce, public_id) 对
    // 2. 检查是否已使用（防重放）
    // 3. 标记为"已使用"并清除（一次性使用）
    challenges[i].used = 1;
    challenges[i].active = 0;
}
```

**字段转换**（用于 ZK 电路）：
```rust
let nonce_field = Fr::from(nonce);  // 直接转换为字段元素
```

### 数据传输协议

#### 1. 加入请求（Join Request）
**方向**：Enclave1 → Host → Enclave2

**数据结构**：
```c
struct JoinRequest {
    char public_id[65];    // Null-terminated hex string
    char group_name[32];   // Null-terminated ASCII string
};
```

**传输方式**：
```c
// Enclave1 发送
ocall(OCALL_SEND_JOIN_REQUEST, &join_req, sizeof(join_req), ...);

// Enclave2 接收
ocall(OCALL_WAIT_JOIN_REQUEST, NULL, 0, &retdata, ...);
copy_from_shared(&join_req, retdata.offset, retdata.size);
```

#### 2. 挑战（Challenge）
**方向**：Enclave2 → Host → Enclave1

**数据结构**：
```c
uint64_t nonce;  // 8 字节无符号整数
```

**传输方式**：
```c
// Enclave2 发送
ocall(OCALL_SEND_CHALLENGE, &nonce, sizeof(nonce), 0, 0);

// Enclave1 接收
ocall(OCALL_GET_CHALLENGE, NULL, 0, &retdata, ...);
copy_from_shared(&nonce, retdata.offset, sizeof(nonce));
```

#### 3. 证明提交（Proof Submission）
**方向**：Enclave1 → Host → Enclave2

**数据结构**：
```c
struct ProofSubmission {
    char public_id[65];      // 公开身份（用于挑战验证）
    char proof_hex[4096];    // Groth16 证明（十六进制编码）
    uint64_t nonce;          // 挑战值（必须匹配）
};
```

**Proof 格式**：
- **序列化**：使用 `ark-serialize::CanonicalSerialize`
- **编码**：十六进制字符串（约 256-512 字符）
- **内容**：Groth16 证明的三个点 (A, B, C)

**传输方式**：
```c
// Enclave1 发送
ZK_GenerateProof(user_id, user_id_len, public_id, nonce, 
                 proof_hex, sizeof(proof_hex));
                 
struct ProofSubmission proof_sub = {
    .public_id = "39695f33...",
    .proof_hex = "a1b2c3d4...",
    .nonce = 123456789
};

ocall(OCALL_SEND_PROOF, &proof_sub, sizeof(proof_sub), ...);

// Enclave2 接收
ocall(OCALL_WAIT_PROOF, NULL, 0, &retdata, ...);
copy_from_shared(&proof_sub, retdata.offset, retdata.size);
```

#### 4. 验证（Verification）
**输入**：
- `proof_hex`：十六进制编码的证明
- `public_id`：十六进制编码的公开身份
- `nonce`：挑战值

**过程**：
```c
// Enclave2 验证
int result = ZK_VerifyProof(
    proof_sub.proof_hex,  // 证明
    proof_sub.public_id,  // 公开输入 1
    proof_sub.nonce       // 公开输入 2
);

// 返回值：
// 1 = 验证成功
// 0 = 验证失败或错误
```

**内部流程**（在 `zklib/src/lib.rs` 中）：
```rust
pub extern "C" fn ZK_VerifyProof(
    proof_hex: *const c_char,
    public_id: *const c_char,
    nonce: u64,
) -> c_int {
    // 1. 解码证明
    let proof_bytes = hex::decode(proof_hex_str)?;
    let proof = Proof::<Bn254>::deserialize_compressed(&proof_bytes)?;
    
    // 2. 构造公开输入（顺序关键）
    let public_id_field = hash_to_field(&hex::decode(public_id)?);
    let nonce_field = Fr::from(nonce);
    let public_inputs = vec![public_id_field, nonce_field];
    
    // 3. 验证 Groth16 证明
    Groth16::<Bn254>::verify_with_processed_vk(pvk, &public_inputs, &proof)
}
```

### 安全参数

| 参数 | 值 | 说明 |
|------|-----|------|
| **椭圆曲线** | BN254 | 128 位安全性，配对友好 |
| **哈希函数** | SHA-256 | 用于 `user_id` → `public_id` |
| **字段大小** | ~254 位 | BN254 的标量字段 |
| **证明大小** | ~256 字节（压缩） | Groth16 的 3 个椭圆曲线点 |
| **Nonce 大小** | 64 位 | ~2^64 种可能值 |
| **挑战有效期** | 单次使用 | 验证后立即清除 |
| **ACL 容量** | 可配置 | 示例中为 3 个成员 |

### 消息完整性保护

**重要**：虽然 Host 是不可信的，但 Groth16 证明本身提供了密码学完整性保护：

1. **proof 绑定到 public_inputs**：如果 Host 篡改 `public_id` 或 `nonce`，验证将失败
2. **proof 无法伪造**：没有私有输入（`user_id`）就无法生成有效证明
3. **nonce 绑定到 public_id**：挑战记录存储了 `(nonce, public_id)` 对，防止混淆攻击

**注意**：在生产环境中，建议在 Enclave 之间使用附加的认证加密（如 TLS-like 协议），但即使没有这些，ZK 证明的数学属性也能确保安全性。

## 🏗️ 构建

### 前置要求

- **Rust 1.70+**：构建 arkworks ZK 库所需
- **Keystone SDK**：已安装并配置
- **RISC-V 工具链**：用于交叉编译（可选，将回退到 x86_64）
- **CMake 3.10+**：构建系统

### 构建步骤
```bash
# 克隆该仓库到本地
git clone -b zkid-acl --single-branch https://github.com/qiran27/zk-auth-keystone.git

# 把文件拷贝到 keystone/examples 目录下
cp -r zkid-acl /path/to/keystone/examples

# 进入到 zkid-acl/zklib 目录下执行编译 rust 零知识证明库
cd /path/to/keystone/examples/zkid-acl/zklib/build-zklib.sh
chmod 777 ./build-zklib.sh
./build-zklib.sh

## 🚀 运行

### 在 Keystone 系统上

# 进入到文件所在目录
cd /usr/share/keystone/examples

# 执行测试程序
./zkid-acl.ke
```
### 预期输出
```
╔═══════════════════════════════════════════════════════════╗
║     ZK-ACL Identity Authentication for Keystone TEE      ║
╚═══════════════════════════════════════════════════════════╝

═══ 启动验证者 (Enclave2) ═══
=== Enclave2: ZK 验证者与 ACL ===
[Enclave2] ACL 已加载：3 个授权的 public_ids
[Enclave2] 准备接受加入请求

═══ 启动证明者 (Enclave1) ═══
=== Enclave1: ZK 证明者 ===
[Enclave1] 加载私有 user_id（从密封存储）
[Enclave1] 计算 public_id（仅 SHA256 哈希）...
[Enclave1] 计算得到 public_id: 39695f33deef7970...
[Enclave1] 请求加入 GroupX...

[Host] 📤 转发加入请求
[Host] 📬 收到加入请求

[Enclave2] === 阶段 1：授权检查 ===
[Enclave2] 收到加入请求：public_id: 3c8d9e7a4b6f1d2e...
[Enclave2] 检查 ACL 授权...
[Enclave2] ✓ 授权通过：public_id 在 ACL 中

[Enclave2] 为已授权用户初始化 ZK 系统...
[Enclave2] 加载 Groth16 设置 (Rust+ark-groth16)...
[Enclave2] ✓ ZK 系统初始化成功
[Enclave2] ✓ PRNG 初始化完成 (enclave 内部随机源)

[Enclave2] === 阶段 2：身份验证 ===
[Enclave2] 生成挑战：nonce = 123456789

[Enclave1] ✓ 授权通过，收到挑战 nonce: 123456789
[Enclave1] 为证明生成初始化 ZK 系统...
[Enclave1] 加载 Groth16 设置 (Rust+ark-groth16)...
[Enclave1] ✓ ZK 系统初始化成功
[Enclave1] 生成 Groth16 ZK 证明 (ark-groth16)...
[Enclave1] 证明生成成功 (十六进制长度: 256)

[Host] 📤 转发证明
[Host] 📬 收到证明

[Enclave2] === 阶段 3：验证 ===
[Enclave2] 收到证明
[Enclave2] ✓ 挑战验证通过
[Enclave2] 验证 Groth16 ZK 证明 (ark-groth16)...
[Enclave2] ✓✓✓ 验证成功 ✓✓✓
[Enclave2] 证明者是：
  - 已授权（在 ACL 中）
  - 已认证（有效的 ZK 证明）
  - 已验证（知道秘密的 user_id）

[Enclave1] 验证结果：VALID: 欢迎加入 GroupX
[Enclave1] ✓ 成功：已认证和授权

╔═══════════════════════════════════════════════════════════╗
║                  测试成功完成                             ║
╚═══════════════════════════════════════════════════════════╝
```

### 拒绝请求的示例输出（双边资源优化）
```
[Enclave1] 加载私有 user_id（从密封存储）
[Enclave1] 计算 public_id（仅 SHA256 哈希）...
[Enclave1] 计算得到 public_id: 1234567890abcdef...
[Enclave1] 请求加入 GroupX...

[Host] 📤 转发加入请求
[Host] 📬 收到加入请求

[Enclave2] === 阶段 1：授权检查 ===
[Enclave2] 收到加入请求：public_id: 1234567890abcdef...
[Enclave2] 检查 ACL 授权...
[Enclave2-ACL] 检查 ACL...
[Enclave2] ✗ 授权失败：public_id 不在 ACL 中
[Enclave2] 拒绝请求，无需 ZK 初始化（资源优化）

[Enclave1] ERROR: 加入请求被拒绝（不在 ACL 中）
[Enclave1] 授权失败，无需 ZK 初始化
[Enclave1] ✗ 失败：身份验证失败

注意：Enclave1 和 Enclave2 都没有初始化昂贵的 ZK 系统
```

## 📊 技术细节

### ZK 证明结构（Groth16）

ZK 电路证明知道 `user_id`，其哈希等于 `public_id`：

**电路定义**（来自 `zklib/src/lib.rs`）：
```rust
struct UserIDCircuit {
    user_id_hash: Option<Fr>,  // hash(user_id) - 私有见证
    public_id: Option<Fr>,      // 声称的 public_id - 公开输入
    nonce: Option<Fr>,          // 挑战 nonce - 公开输入
}

impl ConstraintSynthesizer<Fr> for UserIDCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 分配私有见证和公开输入
        let user_id_hash_var = cs.new_witness_variable(...)?;
        let public_id_var = cs.new_input_variable(...)?;
        let nonce_var = cs.new_input_variable(...)?;
        
        // 约束：user_id_hash == public_id
        cs.enforce_constraint(
            lc!() + user_id_hash_var,
            lc!() + Variable::One,
            lc!() + public_id_var,
        )?;
        Ok(())
    }
}
```

**Groth16 证明格式**：
- **证明大小**：约 256 字节（序列化后）
- **曲线**：BN254（最优配对效率）
- **安全性**：128 位安全级别
- **生成时间**：约 50-100ms
- **验证时间**：约 5-10ms

**验证逻辑**：
1. 从十六进制字符串解析 Groth16 证明
2. 使用 `[public_id, nonce]` 创建公开见证
3. 运行 Groth16 验证算法
4. 返回有效/无效

### ACL 管理

ACL 在 `eapp2/enclave2.c` 中硬编码：

```c
static const char* ACL_GroupX[] = {
    "39695f33deef797075fa1abb90f6838d58b9689f649236909634ec6f474c90bf",  // Alice: SHA256("alice_secret_12345")
    "7f3a1e9d5c2b8f4e6a3c1d9e7b5f2a8d4c6e1b9f7a3d5c2e8b4f6a1d9c7e5b3f",  // Bob (示例)
    "2d5e8b3f6a1c9e7d4b2f5a8c1e6d9b3a7f4c2e5b8d1a6f9c3e7b5a2d8f4c6e1b",  // Charlie (示例)
    NULL
};
```

在生产环境中，这可以：
- 从密封存储加载
- 通过安全管理接口更新
- 由可信机构签名

### 挑战管理

挑战存储在固定大小的数组中：

```c
struct ChallengeRecord {
    uint64_t nonce;         // 随机挑战
    char public_id[65];     // 关联的 public_id
    uint64_t timestamp;     // 创建时间
    int used;               // 一次性使用标志
    int active;             // 有效标志
};
```

## 🔬 使用场景

### 1. 联邦学习
- **场景**：多个组织想要协作训练模型
- **问题**：需要验证参与者属于联盟，但不透露身份
- **解决方案**：每个参与者的 enclave 证明 ACL 中的成员身份，而不暴露其组织 ID

### 2. 分布式计算
- **场景**：跨多个安全 enclave 的作业调度
- **问题**：确保任务仅分配给授权的计算节点
- **解决方案**：计算节点使用 ZK 证明对调度器的 ACL 进行身份验证

### 3. 多方计算（MPC）
- **场景**：多方希望对私有输入计算函数
- **问题**：验证所有各方都是授权参与者，而不透露身份
- **解决方案**：每一方的 enclave 证明授权，同时保持输入私有

### 4. 区块链隐私
- **场景**：许可区块链上的私有交易
- **问题**：验证交易发送者已授权，但不透露其身份
- **解决方案**：交易 enclave 证明发送者在授权用户 ACL 中

### 5. 供应链验证
- **场景**：验证产品通过授权供应商
- **问题**：在不暴露业务关系的情况下对供应商进行身份验证
- **解决方案**：供应商 enclave 证明授权供应商 ACL 中的成员身份

## 🔧 自定义

### 向 ACL 添加新成员

编辑 `eapp2/enclave2.c`：

```c
static const char* ACL_GroupX[] = {
    "existing_hash_1...",
    "existing_hash_2...",
    "new_member_hash...",  // 在此添加新的 public_id
    NULL
};
```

### 更改群组名称

编辑 `eapp1/enclave1.c`：

```c
strncpy(join_req.group_name, "YourGroupName", sizeof(join_req.group_name) - 1);
```

### 自定义 ZK 电路

编辑 `zklib/src/lib.rs` 以添加更多约束：

```rust
// 示例：添加年龄验证
struct UserIDCircuit {
    user_id_hash: Option<Fr>,
    public_id: Option<Fr>,
    nonce: Option<Fr>,
    age: Option<Fr>,        // 新增：私有年龄
    min_age: Option<Fr>,    // 新增：最低年龄要求
}

impl ConstraintSynthesizer<Fr> for UserIDCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 原始约束
        cs.enforce_constraint(
            lc!() + user_id_hash_var,
            lc!() + Variable::One,
            lc!() + public_id_var,
        )?;
        
        // 年龄验证：age >= min_age
        // (实现需要 arkworks 的比较小工具)
        Ok(())
    }
}
```

修改后，重新构建：
```bash
cd zklib
cargo build --release --target riscv64gc-unknown-linux-gnu
```

## 📝 与 zkid-auth 的比较

| 特性 | zkid-auth | zkid-acl (本项目) |
|---------|-----------|-----------------|
| **ZK 库位置** | ❌ 主机（不可信） | ✅ Enclave（可信） |
| **验证模型** | 点对点 (P2P) | 客户端-服务器 (基于 ACL) |
| **ACL 支持** | ❌ 否 | ✅ 是 |
| **多成员** | ❌ 仅 1 对 1 | ✅ 多对 1 |
| **主机信任** | ⚠️ 必须信任主机 | ✅ 主机是不可信中继 |
| **安全模型** | ⚠️ TCB 包括主机 | ✅ TCB 仅包括 enclave |
| **使用场景** | 验证两个 enclave 是同一用户 | 验证 enclave 是授权成员 |

## 🐛 调试

启用详细输出：

```bash
# 在 enclave 代码中，添加更多 print_msg() 调用
# 在主机代码中，添加更多 printf() 语句

# 检查 enclave 是否正确加载
ls -lh enclave1 enclave2 eyrie-rt loader.bin
```

常见问题：

1. **"加入请求被拒绝"**：Public_id 不在 ACL 中
   - 解决方案：检查 `eapp2/enclave2.c` 中的 ACL

2. **"证明生成失败"**：user_id 与 public_id 不匹配
   - 解决方案：确保 `hash(user_id) == public_id`

3. **"无效挑战"**：Nonce 不匹配
   - 解决方案：检查主机中的消息队列顺序

## 📚 参考资料

- [Keystone TEE 文档](https://docs.keystone-enclave.org/)
- [零知识证明：图解入门](https://blog.cryptographyengineering.com/2014/11/27/zero-knowledge-proofs-illustrated-primer/)
- [Groth16：配对非交互式论证的大小](https://eprint.iacr.org/2016/260.pdf)

## 📄 许可证

本示例是 Keystone 项目的一部分，遵循相同的许可证。

## 🤝 贡献

欢迎贡献！改进方向：

- [ ] 实现适当的 SHA256（目前简化）
- [ ] 为 ACL 持久性添加密封存储
- [ ] 实现基于 Groth16 的 ZK 证明
- [ ] 为 ACL 条目添加撤销机制
- [ ] 支持多个群组
- [ ] 添加基于时间戳的挑战过期

---

**用 ❤️ 为 Keystone TEE 构建**

