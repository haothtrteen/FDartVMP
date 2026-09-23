# FDartVMP

**Flutter 源码级虚拟机保护系统。** 敏感 Dart 函数被编译成私有指令集、加密后嵌入原生库，由一台私有
解释器执行——所以原始逻辑从不存在于 `libapp.so` 中。

**作者：** haothtrteen · **联系：** 2557976190@qq.com · **双许可：** 开源用
AGPL-3.0-or-later，闭源产品用商用许可——见 [LICENSING.md](LICENSING.md)。

**来试着破它：** 仓库里带了一个用本项目最强配置构建的 CTF 靶子，见
[docs/CHALLENGE.md](docs/CHALLENGE.md)（靶子、规则与预期难度）。

## 命名

项目名是 **FDartVMP**（F 指 Flutter）。Dart 包名、CMake target 和出货库名保持原样——
`dartvmp`、`vmpc`、`libdartvmp.so`——因为它们已经进了构建产物：库名出现在每个 APK 里，
`.so` 名在保护门禁的白名单里，改名的收益为零而波及面很宽。项目一个名字，代码一套稳定名字。

面向 Flutter 的**源码级虚拟机保护（VMP）**系统。把敏感的 Dart 函数编译成私有指令
集，加密后嵌入原生库，由私有解释器执行——原始逻辑在 `libapp.so` 中从未存在过。

这不是方案文档，是可运行的实现，闭环完整：编译 → 保护 → 运行 → 验证。编译器 33
个测试、App 端 31 个测试全部通过，保护效果直接对着实际产出的 APK 做校验，Windows
release 可执行文件也被真正启动并截图，九个受保护函数全绿。

> English version: [README.md](README.md)

---

## 一、要解决的问题

Flutter 的 AOT 产物 `libapp.so` 是一个包含 **Dart VM 快照（Snapshot）**的 ELF 文
件，不是标准 NDK 机器码。它没有 `JNI_OnLoad` 入口，所以通用的 SO VMP / DEX VMP 工
具无法套用——强行套用会破坏快照结构，App 直接无法初始化。

破局思路不是去硬刚快照里的机器码，而是**把敏感逻辑整个搬出 Dart**：

```
核心算法  →  私有字节码  →  加密  →  嵌入 C 层
   ↑                                    ↓
 Dart 桩函数  ←──  FFI 返回  ←──  私有虚拟机执行 ─┘
```

攻击者逆向 `libapp.so` 只能看到一个一行的桩函数。真正的逻辑只以字节码形式存在于原
生库中，且仅在单次调用期间以明文形式存在。

### 为什么不用 dart_eval

原方案建议用 `dart_eval` 作为编译器和运行时。它是个好项目，但它**没有解决真正关键
的那一层**：

| | 自建 VM（本仓库） | dart_eval |
|---|---|---|
| 编译器 | 约 1200 行 Dart | 白送 |
| **C 层解释器** | 约 700 行 C | **仍然要写** |
| 字节码对 Dart 工具链不可见 | 是——从不是 Dart 对象 | 否——它就是一个 Dart `Program` |
| 私有指令集 | 原生支持 | 需要 fork 才能改 |
| 结果 | 逻辑真正从 `libapp.so` 中消失 | 逻辑只是挪了位置，没有隐藏 |

`dart_eval` 的运行时是**纯 Dart** 的。要让它的字节码「在 C 层执行」，你必须把一个
Dart 运行时嵌进 C——而这恰恰会把本设计要避开的那个 Dart VM 快照重新拖进来。所以
dart_eval 省掉的是编译器，把难的那一半留下了。

解释器无论如何都得写；而一旦决定自己写，**把小指令集和小编译器一起设计，比去适配别
人 opcode 编码的 fork 更省事**。这就是本仓库自带 VM 的原因。

架构上刻意保留了干净的边界，后续想接 dart_eval 前端只需替换编译器：任何能产出
`packages/dartvmp/src/dvmp_wire.h` 中那套指令集的编译器，都能直接复用现有运行时。

---

## 二、架构

```
protected/*.dart              真实实现（不在 App 中）
        │
        │  tool/vmpc:  词法 → 语法 → AST → 字节码 → opcode 置换
        │              → 流密码 → 容器
        ▼
packages/dartvmp/generated/vmp_module.inc     掩码后的 uint64 镜像（C 头文件）
        │
        │  CMake（Windows：静态链接；Android：libdartvmp.so）
        ▼
app/lib/generated/protected_stubs.dart        App 调用的一行桩函数
        │
        ▼
Dart FFI  ──►  C 层解释器（dvmp_vm.c）  ──►  23 个已审计的内置函数
                     │
                     └── 受保护内存：解密 → 执行 → 擦除 → 重新加密
```

### 三层保护

1. **私有指令集。** 每个 opcode 字节在写入前先做置换：对 0..255 全字节域做一次**带密钥的
   Fisher-Yates 洗牌**（由 build seed 派生，`Packer.opcodePermutation` / `dvmp_module.c` 里的
   `op_tables`），所以编译器用的 opcode 编号永远不会出现在线上。要还原指令流，必须同时破掉
   这一层**和**流密码。它替换掉的旧写法是 `perm(op) = (op * 167 + seed_byte) mod 256`——那个
   容器 128 次尝试就能交出来；见
   [加强了什么](#加强了什么以及有意没做什么) 的第 7 项和它的反向测试 `tool/recover_opcodes.py`。
2. **流密码。** 用 SplitMix64 生成密钥流，对整个 body 做 XOR。种子**每次调用都会轮
   换**，调用结束后**工作缓冲区**被重新加密——所以在两次调用之间抓这个缓冲区的
   dump，既与磁盘上的二进制不一致，两次 dump 之间也不共享密钥流。但种子本身就在容器
   头部，因此它是**混淆，不是秘密**——详见
   [明文到底在哪里](#明文到底在哪里)。
3. **静态镜像掩码。** 容器以 187 个 word 存储，每个 word 都与一个由 build id 派生的、
   与位置相关的掩码做 XOR，因此 `DVMP` 魔数用 `strings` / `binwalk` 扫不出来。

### 验证了什么，怎么验证的

| 结论 | 校验方式 |
|---|---|
| AOT 快照中没有受保护逻辑 | `tool/verify_protection.ps1` 扫描 `libapp.so` |
| 原生库中没有算法数据 | 同一脚本扫描 `libdartvmp.so` |
| 没有受保护名字进入出货字符串 | 同一脚本的名字探针，且现在会把"桩声明名"和"泄露"分开判定，而不是只报一个数字 |
| 出货快照里没有开发期 oracle | 同一脚本检查 benchmark 基线已消失 |
| 镜像确实被掩码 | `tool/verify_image.py` 解掩码后比对 |
| 只导出了执行 ABI | `tool/list_symbols.py`，同一脚本调用 |
| 字节码与生成器一致 | `tool/walk_bytecode.py` 独立解码，校验 canonical CRC 与认证 tag，并可用 `--tamper` 反向自证 |
| 描述符布局没有漂移 | 同一脚本与 `tool/verify_descriptors.py` 都断言两个 reserved 字段为 0 |
| 指令仓库无法离线解密 | `app/test/vmp_e2e_test.dart` 断言其密钥既不是出货种子、也不是上一次调用的密钥 |
| 明文窗口确实在调用之间关闭 | 同一文件断言调用返回后 body、已解码槽位、指令仓库全都归零 |
| 一次调用无法让整个程序常驻 | 同一文件断言 `峰值槽位 × 最大函数 < 指令流总字节`，且在缓存已填热后测量 |
| 一次调用不泄漏原生内存 | 同一文件跑 256 次调用，要求受保护字节数前后完全相等 |
| 桌面 runner 里确实有运行时 | `tool/capture_desktop_run.ps1 -CheckOnly`，由 `tool/test.ps1 -Release` 执行 |
| 桌面应用真的能跑起来 | `tool/capture_desktop_run.ps1` 启动 release 可执行文件并截图 |
| C 层交接确实找得到目标 | `tool/apply_vmpacker.ps1`——声明的目标在符号表里找不到就拒绝运行；库不是 AArch64、目标的辅助函数留在外面、或者只翻译了一部分，同样拒绝 |
| 被虚拟化的目标里没有 VMPacker 的 VM 执行不了的东西 | 同一个脚本反汇编每个目标，遇到 `bl`/`blr`/`adrp`/`adr`/`[pc,…]` 就拒绝并报出指令与偏移 |
| 受保护的库**真的能跑** | `tool/verify_device_run.ps1` 把重打包的 APK 装到真机上跑，出现崩溃记录就失败——本表里唯一真正执行产物的检查 |
| ABI 入口点没有被 patch | `dvmp_integrity.c` 扫描九个入口点偏移 0 处的分支；它的解码器要用已知编码**和**真实入口点做自检；`app/test/vmp_e2e_test.dart` 会真写一个 hook 上去，要求判定点名那个函数 |
| 运行期确实持有着容器声明的策略 | `dartvmp_guard_probe` 暴露运行期自己的视图（mode/budget/window/used）；`app/test/vmp_challenge_test.dart` 逐个函数与 manifest 对比 |
| 声明的策略是被执行的，而不只是被编码进容器 | 同一文件把**桩**路径推过预算，并要求得到 `TOO_MANY_CALLS` 拒绝 |
| 多线程并发调用结果一致 | `tool/verify_concurrency.ps1`（C harness，8 线程） |
| 被测产物出自同一次构建 | 同一文件比对运行时的 build id 与 manifest 记录 |
| 发布版没有反调试后门 | `tool/verify_antidebug_gate.ps1` 构建两种配置并对比 |
| 保护面没有静默缺项 | `vmpc check` 断言 `// @vmp` 数量 == 编译出的函数数 |
| 解释器每条操作数读取都有边界检查 | `tool/audit_operands.py` 逐指令对照 `kWidth[]` |
| VM 计算结果与 Dart 一致 | `app/test/vmp_differential_test.dart` |
| 生成器与运行时逐字节一致 | `tool/vmpc/test/image_contract_test.dart` |
| 声明的调用策略不可能拒绝合法调用方 | `app/test/vmp_e2e_test.dart` 按已文档化的合法突发量打满，要求每一次都成功 |

其中**对拍测试（differential suite）是最重要的一个**：它把每个受保护函数都送进解释
器执行，再与原始 Dart 实现逐个比对结果，输入覆盖大量样本、包含 64 位回绕等边界情况。

上表有一处不对称，值得明说而不是含糊过去：**篡改检测**这条结论目前是由
`tool/vmpc/test/image_contract_test.dart` 证明的——它在 Dart 侧跑打包器和 tag/CRC
计算。运行时自己的校验路径（`dvmp_module.c` 的 `module_open_locked`）只是被**间接**
覆盖：每次调用都会经过它，所以校验**坏掉**会让整个套件失败；但如果它**悄悄不再触发**，
则不会被发现——因为没有任何东西会给出货运行时喂一个损坏的容器。要真正补上，需要一个
接受任意容器并报告拒绝原因的诊断入口；在那之前，"改字节会被拒绝"这条应视为**生成器侧**
已验证。

### 用别人的工具看：Blutter 的结果

上面所有结论都是本项目自己验自己。更强的检验是用**别人的工具**，而对 Flutter 应用来说
那个工具就是 [Blutter](https://github.com/worawit/blutter)：它把 AOT 快照还原成可读 Dart，
带逐函数反汇编——类、方法名、对象池、每个函数的 ARM64。拿它跑本应用的 **release**
`libapp.so`，是不上完整反编译器前提下能拿到的最狠的静态视角。

**结论：受保护函数体不在里面。** Blutter 还原出了 9 个桩里的 7 个（另外两个
`base32Index`、`checkSum` 只被受保护模块内部调用，App 侧从来没引用过，被 tree-shaker 摇掉
了）。这 7 个每一个都只有三件事：建参数列表、用常量 id 调本地入口、对返回值做类型检查。
`selfTest` 被还原出来的全部内容：

```
static bool selfTest() {
  // ** addr: 0x28f398, size: 0x80
  r1 = <Object?>; r2 = 0
  r0 = _GrowableList()          ; 空参数列表
  r1 = 8
  r0 = call()
      bl  #0x28f418  ; [package:dartvmp/dartvmp.dart] Vmp::call
  ... IsType_bool_Stub ...
  ret
}
```

这是 128 字节的**参数编组**。id 是立即数（`add`=0、`normalizeKey`=2、`verifyLicense`=4、
`deviceToken`=5、`commandChecksum`=6、`makeLicenseKey`=7、`selfTest`=8），所以攻击者拿到的
是一张**分发表**，不是实现。这些 id 从来就不是秘密——桩声明必须有名字，业务代码才调得到。

同一次运行里的其余检查：

| 检查项 | 结果 |
|---|---|
| `protected/licensing.dart`、`protected/keys.dart`、`licensing`、`keys.dart` | 不存在 |
| `kAlphabet`（canary）、`kLicenseSeed` | 不存在 |
| `2654435761`、`1048576`、`1099511628211`（算法常量） | 不存在 |
| 开发期 benchmark 基线及其混合表达式 | 不存在——release 快照确实是摇过的那一份 |
| 受保护函数体 | 只剩 FFI 桩，每个 0x80–0xe4 字节 |

否定结论的价值取决于**正对照**，所以：同一份快照里，Blutter 明确还原出了 `demo-seed`、
`pixel-7`、`1700000000`、`DartVMP demo`，以及真正的算法代码——`wire.dart` 的字节读取器
连边界检查（对列表长度）、下标自增和 `ldrb` 数组载入都还原出来了。**这个工具能忠实还原本
应用的 Dart。** 只是在真正要紧的那几个函数上，它没有东西可还原。

**但它确实找到了一件事，而且是我们自己的错——第二次 Blutter 跑又找到了更多。** 就在那些桩旁边，
对象池里躺着一份**整个机制的明文描述**，来源有两处：

- Demo 自己的 "How this works" 卡片，点名了 `protected/*.dart`、`tool/vmpc`、opcode 置换、
  掩码 uint64 镜像、打包参数缓冲区、以及每次调用重新播种；
- `packages/dartvmp` 里的诊断绑定：它们的 `lookupFunction` 字符串字面量
  （`dartvmp_plaintext_probe`、`dartvmp_body_residue`、`dartvmp_session_probe`……）把每个探针
  **揭示了什么**都写在了名字里——尽管探针本身在 release 运行时里已经被编译掉了。

两处都放到了 `kReleaseMode` 后面，`verify_protection.ps1` 也为此长了第三张探针表——12 条机制**短语**，
扫 `libapp.so`。这个修复对那 12 条是有效的。**然后新一次 Blutter 跑直接绕过了它们全部**——因为短语表
只能抓住你已经知道的那次泄露。它找到的是：

| 泄露进快照的 | 为什么要紧 |
|---|---|
| `"the shipped module image is not a DVMP container"` | 点名了容器**魔数**——而 `tool/verify_image.py` 存在的意义就是让它不出现在二进制里，并断言它不在生成的字面量中。Dart 的错误表把它还回来了 |
| `"invalid opcode in the module image"` | 点名了私有指令集 |
| `"bad argument across the VMP boundary"`、`"internal VMP error"`、`"unknown VMP status"`、`"the VMP arena ran out of memory"` | 同一张错误表里的另外四条，直接点名机制 |
| `" does not fit in the VM's signed 64-bit slot"` | 点名了 VM |
| `"dartvmp_instrumented_probe"`、`"dartvmp_antidebug_force"` | 两个**最新**的探针绑定——它们在守卫写好之后才加进来，而且没带守卫 |
| `"Every row below executed inside the native private VM. No Dart implementation of these functions exists in this application."`，以及性能卡片的 `"deviceToken() runs 512 mixing rounds"` | Demo 在描述自己的设计，连轮数都给了 |

现在全部在源码层面修好，而且每处修复都有理由、不是改措辞：错误表只描述**调用者遇到了什么**，绝不描述
保护是怎么搭的；两个漏掉守卫的绑定补上了守卫；Demo 文案在 release 里改为中性表述，详细版本仍留在源码里
供非 release 构建使用；`wire.dart` 的异常改为说明允许的类型，而不是那道边界的缩写。

**而且这道检查现在是"类别"而不是"清单"。** `verify_protection.ps1` 会在 `libapp.so` 里搜十七个**机制
词**（`DVMP`、`VMP`、`opcode`、`bytecode`、`permut`、`SplitMix`、`mask key`、`private VM`、
`native interpreter`、`masked uint64`、`packed argument`、`protected/*.dart`、`tool/vmpc`、
`mixing rounds`、`instrumented_probe`、`antidebug_force`）加上原来那八条短语，另有十三个**带理由**
白名单的名字：`libdartvmp.so` 和九个 `dartvmp_*` ABI 名字无论如何都能在 APK 的 zip 目录和 `.dynsym`
里看到，把它们当泄露是**安全表演**，而 `DartVMP` 是应用标题里的产品名（它把 `VMP` 当成子串包含，
所以扫描前会先把白名单字符串抹掉）。反向验证方式和以前一样：对 Blutter 分析的那份 APK 跑会报出九条
泄露并附上下文，对重新构建的那份跑一条都没有。

两处**不是措辞**的失败，现在都是回归检查：

- **漏掉守卫的绑定。** 它们上面的注释写着"下面每个诊断绑定在 release 构建里都会提前返回"，而有两个没有。
  注释管不了这件事，所以 `app/test/vmp_e2e_test.dart` 现在会走一遍 `bindings.dart`：每个以 `_bind` 开头
  的 `static` 方法，必须**先**经过 `if (kReleaseMode)` 的提前返回才能到达它的 `lookupFunction`。反向验证
  的方式是删掉其中一个守卫，看它是否点名那个绑定。
- **这道检查自己的覆盖面。** 上面那个测试的第一版只扫签名之后 400 个字符——比其中一个绑定上的注释还短，
  于是一个**守卫正确**的绑定被报成了泄露。现在它用花括号匹配整个方法体。和它要防的那个 bug 是同一种失败
  模式，只是高了一层。

**Dart 侧混淆，以及"零个名字"意味着什么。** release APK 现在用
`--obfuscate --split-debug-info=<dir>` 构建，而这件事比预想的更要紧。Blutter 读的是快照里留下的东西，
而普通的 release 快照会保留生成的桩声明及其真名——业务代码调用 `verifyLicense(…)`，所以声明必须这么拼。
混淆会把声明和调用点一起改名，而桩是按数字 id 分派的（`Vmp.call(4, …)`），所以没有任何东西依赖真名。
打开这个开关后，受保护名字在 `libapp.so` 里的出现次数降到**零**，而 `verify_protection.ps1` 现在**要求**
零——旧标准（"在场的名字都是桩声明，因此可以接受"）已经删掉，因为那正是让最后一份映射随货发出的漏洞。

达到这一点用两轮，而第二轮才是有信息量的那半：开启混淆之后，七个名字**仍然**在快照里——因为这个 Demo
把它们印成了自己的行标签（`'verifyLicense(key)'`）。UI 文案正在把第 3 项刚从容器里拿掉的那张
"id → 用途"映射又交出去。现在 release 用 id 标注（`fn[4]`），dev 构建保留真名，而上面那张真机截图就是
混淆后的构建：`fn[0] 42`、`fn[4] true`、`fn[7] ZVEXKFVVCDH93W6R`，每个值仍与参考实现一致。

两个方向都验证过而不是声称：同样的源码**不带** `--obfuscate` 构建时，门禁会点名八条探针里的六条而失败；
带混淆的构建则八条全部缺席、通过。代价要说清楚：符号目录必须随每次发布归档，否则崩溃栈会变成 `a`、`b`、`c`。

**这没有藏住什么，免得把收益说大。** `Vmp.nameOf(id)` 仍然在**运行期**从 `libdartvmp.so` 里的掩码表
解析出名字——Demo 自己的 dispatch 行就印着它们（同一张截图里的 `dispatch [4] verifyLicense / 1 args`）。
把它们从 UI 上去掉是**安全表演**：那个查询是公开 API，而表就在出货的库里。**这一轮做的是静态维度——
Blutter 不运行任何东西就能从 `libapp.so` 读到什么——而在那个维度上，应用现在不带任何映射。**

### 加强了什么，以及**有意没做**什么

清单上是八项。六项已实现并验证；一项在现有工具下做不到，而且是**量出来**的而不是猜的；一项在算清它到底能买到什么之后被否决。
**被否决的那部分更有信息量**——因为它们每一个看起来都像安全，其实不是。

**1. 虚拟化 C 层——套用了、真机测了，结论是：它撑不住。**
拿到容器是机械活（第 2 项去掉了最便宜的那条路，`tool/recover_from_shipped.py` 现在做的是"老实版"）。
攻击者接下来要做的是**读懂字节码**，而这以前很便宜：`dvmp_vm.c` 编出来就是一个可读的 switch，每个
opcode 的语义写得明明白白。这一项本来要关掉的就是这一步。它关掉了一部分，而诚实的总结并不好听：

**第一轮真机实测：虚拟化只对最不值钱的两个函数有效，真正要紧的那些根本套不上。第二轮把那五个里的
三个救了回来。** 七个函数被虚拟化、套用过程干净、所有结构性检查全绿。然后受保护的 APK 装到真机上
（root 的小米 12，Android 13，arm64-v8a），七个里有五个让应用起不来。逐个目标单独测、再逐个限制
在我们自己的 C 层里修掉之后：

| 目标 | 真机表现 | 原因 / 改了什么 |
|---|---|---|
| `keystream_seed` | **正确运行** | 无调用、无全局变量——4 条指令 |
| `apply_keystream` | **正确运行** | 79 条指令：立即数、寄存器搬移、字节读写、分支 |
| `permute_code` | **正确运行** | 原来死在 `0x0`：用 `adrp` 读 `kWidth[]` 表。表改成 `op_width()`（立即数比较链），`CSEL` 也必须去掉 |
| `unpermute_code` | **正确运行** | 原来死在 `0x6dcc`，即 `bl dvmp_vm_set_error` 的地址；消息改由调用方格式化 |
| `dvmp_body_tag` | **正确运行** | 原来死在 `0x6d60`，即 `bl dvmp_fnv1a64` 的地址；哈希内联（一份实现，两个视图） |
| `dvmp_mask_keystream` | SIGSEGV | 调用 `dvmp_sha256`；并且有局部数组 |
| `code_store_build` | SIGSEGV | 调用五个函数 |

"正确运行"指的是**数值**，不是"没崩"：APK 装上去、启动、截屏，演示卡上的每个数字都与 Dart 预言机
核对过——`add(20,22)=42`、`makeLicenseKey("demo-seed",7)=ZVEXKFVVCDH93W6R`、`verifyLicense` 对正确
密钥为 true、改一个字符为 false、`deviceToken("pixel-7",1700000000)=-5031510683369134119`、
`selfTest()=true`。这些调用都是经跳板派发的，而只要 `dvmp_body_tag`、`permute_code`、
`unpermute_code` 三者中任何一个算得和 Dart 汇编器不一样，模块**根本打不开**。测试套件里的真机步骤
只证明"没有崩溃记录"，所以这一项是另外用眼睛核对过的。

前三个的诊断是**出错地址**。VMPacker 1.3 的 VM 只重定位它翻译的那个函数**内部**的分支，别的一概
不管，所以一个外部 `bl` 会保留它的链接时地址，而 VM 跳过去时**没有加上库的加载基址**——这就是为什么
出错地址**等于调用目标**：`llvm-objdump -d` 显示 `dvmp_fnv1a64` 在 `0x6d60`、
`dvmp_vm_set_error` 在 `0x6dcc`，而进程恰好死在这两个地址上。`adrp`/`adr`/PC 相对寻址读全局变量是
同一回事，所以**一条调用都没有**的 `permute_code` 死在了 `0x0`。

第四个没有任何出错地址，而它才是真正有意思的那个。调用、`adrp`、SIMD 都清掉之后，五个目标全部
100% 翻译、APK 装得上、进程也不崩——但每一个受保护调用都失败在
`opcode 0x20 out of range at +0`：解码走第一步就拒绝了指令流的首字节。用真机二分
（`tool/bisect_vmpacker.ps1`，一次加一个目标）定位到 `unpermute_code`，再把它和三个已知正确的目标
对比反汇编，指向了 `CSEL`：它在那里面出现两次（shuffle 的 `r % (256 - i)`，以及逆表 scatter 里的
`i < DVMP_OP_MAX ? i : DVMP_OP_MAX` 选择），而那三个能跑的目标里一次都没有。VMPacker 的 VM **有**
`CSEL` 处理器，所以这条指令算"支持"——它算错了。修法在我们这边而不是在工具里，因为流水线必须能用
**未修改的发布版**跑通：shuffle 改用恒等式而不是取余（`r - ((r + i) >> 8) * (256 - i)`，因为
`i < 38` 且 `r <= 255`，商恰好就是那个移位），逆表改成两次无条件 scatter。这是本项目里唯一一个
**任何字节级检查都抓不到**的失败：它 100% 翻译、运行不崩，唯一的信号是一个算错的数字。

于是 `tool/vmpacker_targets.txt` 现在列五个目标，剩下两个仍然需要调用，挪进 `#+pcrel` 段，由
`tool/apply_vmpacker.ps1` 的**指令覆盖面检查**按名字和偏移拒绝。那个检查是第一轮真正的成果：真机 +
tombstone + 二分花掉的时间，它一秒就能查出来。它反向验证过——对真实库确实会报，比如
`+0x4428 bl 0x9624 <vmp_secure_alloc>`、`+0x4590 adrp x0, ...`（`code_store_build`）。

**活下来的五个目标值多少钱：比那两个多，但仍然不是解释器。**
`apply_keystream` 是用容器头部那个 seed 做密钥的 SplitMix64，`keystream_seed` 就是 `seed ^ 0xA5A5…`；
两者在本文件上面都写得足够详细，照着就能重写，虚拟化它们等于让攻击者多花十分钟写这两个函数。回来的
那三个是另一类目标：`permute_code` 和 `unpermute_code` 就是私有 opcode 映射本身，`dvmp_body_tag` 是
容器的认证标签。想拿到它们，现在要么把构造重新实现一遍，要么逆 VMPacker 的字节码——"读一下反汇编就
知道映射怎么来的"那条路没有了。**没变的是它下面那层**：`dvmp_vm.c` 仍然是可读的 AArch64，所以
"读解释器就知道每个 opcode 干什么"依旧和以前一样便宜。映射的保密性仍然靠第 7 项；这一项提高的是
另一条路线的成本。

下面这一段记的是"套用"周围那三道检查是怎么来的，因为正是它们让目标清单可信，而每一道都是在亲眼看到
它要抓的失败之后才写的：

- **指令覆盖面。** 拒绝 `bl`/`blr` 和 `adrp`/`adr`/`[pc, …]`，并报出偏移。这是唯一一道**不需要真机**就能
  拦住上面五次崩溃的检查，也是唯一能在 APK 构建**之前**起作用的检查。
- **逐目标"全量翻译"。** `-v` 会报 `Translated: N/M`，脚本现在拒绝部分翻译。字节级后置检查看不到这个：
  VMPacker 会为它**看懂的那部分**指令发出跳板，于是"字节变了而且有分支"成立，而函数的其余部分就摆在
  旁边，清清楚楚的 AArch64。
- **辅助函数不许留在外面。** 一个被两个目标调用的 `static` 辅助函数在 `-O2` 下会有自己的函数体，而那个
  函数体正是跳板想藏的东西：攻击者直接调它，永远不进 VM。这不是假设——第一个关键化置换的构建就带出了
  `t op_tables`（`0x4134`），VMPacker 自己的 verbose 输出写得很清楚：`0x0040: BL raw=0x97FFFF0C` 跳进它。
  `DVMP_ALWAYS_INLINE` 修掉了它，`!op_tables` 保证它不再回来。
- **目标必须真的存在**，而且库必须是 AArch64。一个按名字找函数的工具，如果什么都没找到，它会以 0 退出，
  然后发出去一个所有人都以为受保护、实际没受保护的库；而**另一个 ABI** 编出来的 `.so` 符号名一模一样，
  能通过所有按名字做的检查。

**这一项还额外暴露了两个失败，都已在源码层面修掉**，它们都不是 VMPacker 的限制，是我们的：

- **栈金丝雀。** NDK 默认带 `-fstack-protector-strong`，所以任何有局部数组的目标都以
  `mrs x19, TPIDR_EL0` / `ldr x8, [x19, #0x28]` 开头。VMPacker 两条都翻译了，而它的 VM 不复现 TLS 读，
  于是 `x19` 到手是 0，进程死在 `fault addr 0x28`——**字面上就是那条指令里的 `#0x28`**。
  `DVMP_VMPACKER_TARGET` 现在带 `no_stack_protector`，而且是加在**目标**上而不是整个文件上，所以金丝雀
  只在"由 VM 执行"的地方被去掉。
- **SIMD 来自 clang 的*内联 builtin*，不是来自向量化器。**
  `dvmp_mask_keystream` 和 `code_store_build` 翻译不过去（64/70、202/210），卡在 `movi` + `stp q0,q0` 和
  `ldr q`/`str q` 上。`-fno-vectorize -fno-slp-vectorize` **没有任何作用**，这才是意外之处：那些 SIMD 是
  一次 `memset` 展开（256 字节常量填充）、一次 SHA-256 初值的 32 字节常量拷贝、以及一次内联 `memcpy`。
  用 `no_builtin("memset","memcpy")`、把 `uint32_t h[8] = {…}` 换成八次标量赋值、把逆置换表从常量填充改成
  数据相关的 scatter，两者都到了 100%——然后在真机上就露出了**下一个**问题，也就是调用。

**解释器本身：量过了，够不着。** `dvmp_vm_run` 是 ISA 语义所在之处，所以它是唯一能关掉最后一环的目标。
这个工具做不到：打开 `dvmp.vmpacker.hot=true`（它顺带把 `dvmp_vm.c` 也去向量化）之后，它翻译
**1029/1053** 条指令然后中止，剩下 24 条是 SIMD 寄存器里的 16 字节结构体拷贝——解释器自己的值搬运，
不是被向量化的循环——两个 de-vectorize 开关都碰不到。而且想要它本身也是错的：受 VMPacker 保护的函数跑在
第二台解释器上，把内层循环虚拟化等于在每一次受保护调用的每一条字节码指令上套一层 VM 套 VM。开关还在
（`-PcRel` 不含它，见 `tool/vmpacker_targets.txt` 的说明），是**写下来而不是删掉**，以便 VMPacker
补上 SIMD 覆盖和调用解析之后重新决定。

**真机跑一次发现了别的什么都发现不了的东西。** 受保护的 APK 在画出第一帧之前就崩了，而套件当时是
ALL GREEN：`apply_vmpacker.ps1` 报"5/5 目标已替换为 VM 跳板"并回读字节作证，导出面完好，容器 CRC 和
tag 都通过，APK 也装得上。字节级检查回答的是"工具做了事吗"，回答不了"做出来的东西能执行吗"。
现在这一步是独立的——`tool/verify_device_run.ps1`，接进了 `tool/test.ps1 -Release`——正是它把这一项从
"一句声明"变成"一次测量"。它证明的是进程能活过启动、且没有写下崩溃记录；**答案**是否正确要看 demo 屏幕，
上面打印了每个受保护函数的结果和九条 dispatch 记录。两件事都做了：只带那两个可用目标时，受保护的 APK
正常运行，每一个值都与参考实现一致，包括 `makeLicenseKey("demo-seed", 7) = ZVEXKFVVCDH93W6R` 和
`deviceToken("pixel-7", 1700000000) = -5031510683369134119`。

**2. 掩码不再把密钥交给已知明文——已完成。**
`tool/recover_from_shipped.py` 以前能**完全不用反汇编**从 release APK 里把掩码密钥挖出来。三件事凑齐了：
掩码是 `SplitMix64-finalise(key + index + G0)`，在密钥上是**双射**；容器开头 8 字节是**已知明文**
（magic + 版本号）；而且它是**流密码**，知道一个字就推出后面 195 个字。于是
`unmix(word[0] XOR known_header) - G0` 就是密钥，而密钥就是整个容器。

现在换成 `SHA256(le64(key) || le64(index))[0..8)`，改的是**形状**而不只是常数：

| | 以前 | 现在 |
|---|---|---|
| 一个已知字能否推出密钥 | 能，反演即可 | 不能——截断丢掉了 64 位，反演代价约 2^64 |
| 一个已知字能否推出其他字 | 能，它是流 | 不能——每个下标是独立的带密钥函数 |
| 那 8 个头部字暴露了什么 | 全部 196 个字 | 8 个字 |

用 SHA-256 而不是更便宜的东西，是因为它有公开测试向量，能让手写实现**可被检查**：否则一个细微错误的
散列会被 Dart 侧改过去迁就它，容器照样往返正常，测试照样全绿。`tool/verify_crypto.ps1` 跑遍所有
padding 路径的向量，然后再跑攻击。两个方向都验证过：检测器能找出用旧原语掩码的容器（`--selftest`），
而且它抓到了**磁盘上那个真实的旧 APK**，报出 `0x8f3a17c9e7cf471b at offset 0x1c50`——正是之前手工
恢复出来的同一个密钥。对重新构建的 APK，它什么都报不出来。

残余暴露，写清楚免得把收益说大：**密钥仍然随 `libdartvmp.so` 出货**，离线分发要求如此，所以读过
`unmask_image_into` 的攻击者仍能重新推导密钥流。改变的是：这现在需要**去读运行时**，而不是对着二进制
白送的数据做代数。这是实打实的一步，但它不等于"机密性"。

**3. 函数名已不在容器里——用"删掉"的方式完成。**
`walk_bytecode.py` 以前会从解密的容器里直接打印 `fn 4 [verifyLicense]`，把整张 id → 用途表交出去。而有
两件事同时成立：运行时**从来没有读过** `DvmpFuncDesc.name`（名字查找走的是编译进去的掩码表
`kDvmpNameBlob`），而 emitter 里那条"函数名必须在字符串表里，因为 `dartvmp_call_named` 靠它解析"的断言
**根本是错的**。所以这些名字是死重，唯一作用就是把这张表塞进密文里。

**在容器内部**给它们做掩码的方案被考虑并否决了：容器里的一切对解开容器的人都是明文，在那里做掩码只是装饰。
删掉才是能改变攻击者所得的那个版本。字符串表 12 项 → 3 项，容器 1565 → 1398 字节，
walker 现在打印 `fn 4 []`。`tool/verify_descriptors.py` 断言 name 字段为 0，并且反向验证过——
把旧行为的两半都恢复回去，看它确实报错。

**4. 逐函数密钥——否决，因为它会是**安全表演**。**
容器的 body 是用**它自己头部里的 seed** 派生的密钥流加密的。所以任何由这个 seed 派生的逐函数密钥，
对任何拿到 seed 的人都是可得的——也就是任何解开了容器的人。而"解开容器"恰恰是逐函数密钥本应让它变难的那一步。
从一个攻击者已经持有的值派生出 9 个密钥而不是 1 个，什么也没改变。

逐函数密钥真正划算的地方是**运行时**的仓库，而那里已经有了：`code_store_build` 每次 open 抽新熵，
并且**逐函数**派生（`keystream_seed(code_key ^ i)`），正是为了让物化一个函数不暴露另一个的密钥流。
那才是这个想法里真正面对攻击者的版本。

**5. 反调试——接上了，但先改了它的反应。**
这一层本来就在、也接好了（检测到插桩时 `dartvmp_init_locked` 会拒绝初始化），而且它在所有构建里都是关的。
这两半都错了。"全关"意味着出货 APK 里根本没有任何运行期对抗手段；而"拒绝初始化"意味着第一次误报——
一个配错 `TracerPid` 的环境、一个模拟器、厂商的监控代理、一个像 Frida 的端口——就会让应用起不来。
**一个能弄坏应用的保护层，正是本 README 第一条规则禁止的结果。**

现在的反应是把已解码函数缓存从 4 个槽位收窄到**1 个**：在调试器下，明文窗口从"四个函数宽"变成
"一个函数宽"，而解释器返回的答案逐位不变。把缓存清空不是一个选项——正在执行的那条指令要求函数的指令流
保持有效——所以 1 个槽位是最窄的正确设置，而让"1 槽缓存"正确而不只是慢的，正是 `dvmp_code_ensure`
每次取指重新校验槽位身份这件事。彻底拒绝运行仍然可用，走 `-DDVMP_ANTIDEBUG_REFUSE`，需要显式选择，
这样这个取舍是被有意做出的。

它现在**在出货 APK 里是开的**，已在真机上验证（无误报，九个函数全绿），并且
`app/test/vmp_e2e_test.dart` 通过一个只在诊断构建里存在的钩子强制判定，断言两件事：缓存确实变成 1 个槽位，
且每一个受保护函数在被收窄的状态下仍然与参考实现逐位一致。

**6. 天花板，以及唯一的结构性答案。**
暴露链现在是：`libdartvmp.so` 里有掩码密钥 → 密钥打开容器 → 容器里有字节码 →
`libdartvmp.so` 里还有解释器，说明这些字节码是什么意思。**每一环都是"读一样随货发出的东西"。**
第 2、3、5 项都没有去掉任何一环；它们把第一环的成本从一个脚本抬到一次逆向。
**而第 1 项本来要抬高最后一环，结果没有做到**：解释器仍然是普通的 AArch64，因为本该藏住它的那台 VM
执行不了那个函数所用到的指令。第 7 项抬高的**映射**的成本，不是 ISA 的成本——读过 `dvmp_vm.c` 的攻击者
依然知道每个 opcode 干什么，只是还得再重建"哪个字节是哪个 opcode"。

所以天花的诚实表述是：**对于一个必须离线工作的组件，静态还原是**成本**问题，不是**可能性**问题。**
工程能选的是成本有多高，选不了"不可能"。如果某段逻辑必须真正不可还原，唯一的答案是架构而不是混淆——
把它放在服务端，让出货的二进制去调用它。VMP 保护的是那些必须离线工作的部分（策略、派生、以及网络依赖
会让它不可用的那些校验），而这个划分应该按"哪部分值得一次往返"来做，而不是按"混淆器最能藏哪部分"来做。

**7. 私有指令集曾经是"公开字节的仿射映射"——已替换。**
这一项值得单独成条，因为它是整条还原链上最后一个"能被暴力试出来、而不需要重新实现"的步骤，而且它不是
靠审计代码发现的，是靠问"攻击者做完第 1、2 项之后会干什么"发现的。

容器的流密码用**它自己头部里的 seed** 做密钥，所以按构造就是公开的，攻击者离线就能剥掉。挡在他和字节码
之间的就只剩 opcode 置换。它曾经是

```
wire = (op * 167 + (seed & 0xFF)) & 0xFF
```

而 seed 就在头部，于是未知量只剩乘数——乘数必须是奇数，因为 167 与 256 互素、映射必须可逆。那就是
**128 个候选**。`tool/recover_opcodes.py` 就是跑这个攻击的：逐个候选去走指令流，留下那个"正好走完
`code_len`、且每个 opcode 都在范围内"的。容器自己的 CRC 就是判定器，所以结果不是猜的。在那种情况下
虚拟化 `unpermute_code` 一分钱都不值，因为映射本来就会自己掉出来。

现在它是对 0..255 全字节域做的**带密钥 Fisher-Yates 洗牌**，由同一路 SplitMix64 驱动、带一个独立的域分隔
常量，取前 `DVMP_OP_MAX` 个作为线上字节。**没有参数可搜**：还原它意味着找出一个与整条指令流一致的赋值，
搜索空间是 256 个值的置换，而不是 128 个奇数。置换是按需从 seed 重建的，**不缓存**——缓存会成为内存里
第二份映射，等着攻击者去找，而那正是要藏的东西。代价是每个函数物化时做一次 256 字节洗牌，而解释器随后
要跑几千条指令。

`tool/recover_opcodes.py` 现在对出货输出**失败**；而"一个只会说'什么都没找到'的检测器就是一句 print"，
所以它的 `--selftest` 会用旧的仿射映射把同一份 body 重新打包，并且必须把**那个**逐字节还原出来。两个方向
都在 `tool/test.ps1 -Release` 里跑。这个 selftest 立刻就证明了自己的价值：脚本第一版在解码时把自己读到的
**操作数字节清零了**，CRC 判定器因此永远不匹配，于是它对着**任何**输入都说"不是仿射"——包括它本该破解的
那个旧格式容器。那次"攻击失败"，其实攻击从未真正跑过。

**天花板没有移动，这一项也不假装它移动了——而且第 1 项一测，诚实的说法只会更差。** 置换的构造在
`op_tables` 里，被内联进 `unpermute_code` 和 `permute_code`。这两个本来是要交给 VMPacker 的；真机结果表明
它们会崩，所以它们**没有**被虚拟化，构造就以普通的、可读的 AArch64 随货发出。准确的表述是：

- 以前：映射可以**机械地**恢复——128 个候选，用容器自己的 CRC 判定，完全不用读代码；
- 现在：不能再机械恢复，搜索空间从 128 个奇数变成一个 256 值的置换——但读过 `unpermute_code` 那大约
  100 条指令（或者认出 SplitMix64 + Fisher-Yates 循环）的攻击者可以直接重建它。

第 7 项去掉的是那个**脚本**。它没有让映射变成秘密，第 1 项也没有把它藏到跳板后面。这才是本项目能真正
买到的差别，也是为什么全篇的诚实说法是"抬高成本"，而不是"能不能"。

**8. 最便宜的那种攻击此前完全没有设防——入口点完整性校验，已加入。**
上面所有内容针对的都是**想读懂**受保护逻辑的攻击者。而授权 Demo 真正会遇到的攻击比这便宜得多：
**改答案**。直接返回 `true`、拦截产出答案的那个入口点、hook 那次 FFI 调用——这些都不需要读容器、
字节码或解释器，上面七项没有一项碰到它。所以它曾经是本项目最大的未覆盖缺口，而它是靠问"攻击者想要什么"
发现的，不是靠问"设计保护了什么"。

`packages/dartvmp/src/dvmp_integrity.c` 会扫描九个 ABI 入口点，找**偏移 0 处的分支**——无论
Frida 的 Interceptor、Dobby，还是手工 patch，留下的都是这个东西。反应遵守本项目一贯的规则：记录下来，
并入"检测到插桩"那个判定（把已解码函数缓存收窄到 1 个槽位），**永远不改变答案**。彻底拒绝启动仍然
是 `-DDVMP_ANTIDEBUG_REFUSE` 下的选项。

**诚实的上限，和本文件其它部分一样直说**：它只能找到**以分支开头**的 hook。先保存序言再跳的 hook、
或者改调用方的 hook，都找不到——而且知道它存在的人可以把它本身 patch 掉。它去掉的是攻击的**免费版本**，
不是攻击本身。如果某次绕过必须被真正阻止，本地检查做不到，因为进程归攻击者所有。

做的过程里有两件事值得留下，因为它们都是本项目反复撞上的那种模式：

- **第一版有**误报**，而修法让这道检查变得真实了。** 它把任何以无条件分支开头的入口点都报成 hooked，
  于是在 Windows 构建上，三个干净函数被判为被 hook：`dartvmp_last_error`、`dartvmp_secure_bytes_live`、
  `dartvmp_build_id`。它们是一行转发函数，而 MSVC 会把这种函数结尾写成 `jmp` 而不是 call/return，
  于是它们的前四个字节是 `E9 <rel32>` 加 `CC` 填充——和 hook 在前四字节上**逐字节相同**。区分它们的是
  分支**去哪里**：尾调用去同一个模块里的另一个函数，hook 去另一个分配里的跳板。所以现在检查会问这个问题
  （各平台一次模块范围查询；平台答不上来时按"在模块内"处理，于是不确定的情况绝不会被报成 hook）。
- **自检测量的是这个二进制，不是编出来的常量。** 它既用已知编码检查解码器，也要求**每一个真实入口点**
  都判为干净——正是这条断言抓住了上面那个尾调用误报。而 `app/test/vmp_e2e_test.dart` 会把攻击真的做一遍：
  把代码页改成可写，往 `dartvmp_status_name` 的第一条指令上写一个分支，要求判定报出 count 1、并且
  置位的是**那个**函数对应的 bit；然后把字节恢复回去，要求判定重新变干净。一个只被看到过说"干净"的检查，
  只是一句 print。

**没做的，以及为什么它们没被算作"缺口"：**把一堆最终都躺在同一个二进制里的密钥层层嵌套；在密钥同样在
二进制里的第一层之上再套一层密码学；针对**容器格式**的透明度把戏。它们各自都要维护和评审成本，给攻击者
多买几个小时，而更要紧的是——让代码更难推理，而本项目里真正的 bug 全都是靠推理找出来的。上面这些改动
性质正好相反：掩码那个去掉了一条数学捷径，名字那个去掉了数据，反调试那个去掉了一条"保护可以弄坏应用"的路。

### 只有"真跑一次"才能发现的问题

上面那张表全绿，而**出货的 Windows 桌面应用根本起不来**。runner 把运行时编成静态库链进去，
所以整个 bundle 里没有 `dartvmp.dll`；但 `openRuntimeLibrary()` 在所有平台都按名字去开
`dartvmp.dll`，于是应用第一屏写的是：

```
The protected runtime is unavailable
VmpUnavailable: could not open dartvmp.dll: ... (error code: 126)
```

要让这件事发生，得同时踩中两个错，而且它们互相掩盖：

- **插件从来没把运行时链进去。** Flutter 生成的 CMake 只对 `FLUTTER_PLUGIN_LIST` 里的插件
  执行 `target_link_libraries(${BINARY_NAME} PRIVATE ${plugin}_plugin)`；FFI 插件进的是
  `FLUTTER_FFI_PLUGIN_LIST`，那个循环只负责**拷贝**文件。所以
  `packages/dartvmp/windows/CMakeLists.txt` 把静态核心库编出来了，然后丢在地上。补上链接
  也仍然不够：MSVC 链接器会丢掉"没有任何符号引用"的静态库，而 runner 里确实一个
  `dartvmp_*` 都不引用——Dart 侧是运行时用 `GetProcAddress` 拿符号的。必须用
  `/WHOLEARCHIVE` 强制整库链入。只补 `target_link_libraries` 的那一版产出 90 KB、导出表为空的
  exe，然后**报出完全相同的错误信息**。
- **Dart 侧找错了地方。** 运行时既然在可执行文件里，符号就必须用
  `DynamicLibrary.executable()` 拿，而不是 `DynamicLibrary.open('dartvmp.dll')`。Android 正好
  相反：Gradle 插件把 `libdartvmp.so` 打进 APK，那里必须用 `open()`，用 `executable()` 什么
  都找不到。

这两个错都够不到 `flutter test`，而且这是**结构性**的、不是测试疏忽：测试宿主是
`flutter_tester.exe`，它自己不含运行时，所以套件**必须**通过 `DARTVMP_LIBRARY_PATH` 加载
一个另外构建的 DLL——而那恰恰是出货桌面应用不会走的路径。**测试宿主无法覆盖"产品自己怎么
加载自己的代码"这条路径。** `tool/capture_desktop_run.ps1` 就是补这个洞的：它先扫描构建出来的
可执行文件里有没有 ABI 符号（纯链接检查，不需要显示环境，`tool/test.ps1 -Release` 现在会跑），
然后启动真正的 release 可执行文件并截图。当前这次运行显示 `runtime loaded, 9 protected
functions`，以及九行全绿的 `dispatch [0..8]`。

同一次复核还发现 `pubspec.yaml` 把 `ios`、`linux`、`macos` 声明成插件平台，而这三个目录一个
都不存在——包在宣传它没有的支持。这些条目已经删掉；`openRuntimeLibrary` 里的分支保留着，
加平台就是加目录的事。

当前构建的实测数据：

```
编译器测试       33 passed
App 测试         31 passed（16 个对拍 + 15 个保护验证）
libdartvmp.so    9 个导出符号，0 个解释器内部符号
libapp.so        4.2 MB，无受保护常量、无算法数据
                 （有 7 个名字：业务代码要调用的桩函数声明名）
dartvmp_demo.exe 126 KB，运行时已链入，9/9 受保护函数全绿
静态镜像         1565 字节，196 个掩码 word
字节码           9 个受保护函数共 1525 字节
代码常驻         4 个槽位，最大函数 215 字节，指令流合计 958 字节
```

### 一次对抗性复核发现了什么

上面这些结论经过一次独立审计：它从零重建了容器格式、构造任意镜像喂进真实运行时、对活动进程做了跨进程内存 dump，并跑了多线程探针。它找到了真问题，值得列出来——因为**规律比单个 bug 更有用**：

| 发现 | 含义 |
|---|---|
| body 从来没被擦除过 | 文档里的明文窗口是"进程生命周期"而不是"一次调用"——**已修** |
| 文档说有 native lock，实际一个都没有 | 并发调用返回错误答案并崩进程——**已修** |
| `need_builder` 接受任意对象 | 构造的镜像能走到野指针解引用——**已修**（builder 有了自己的 slot tag） |
| `entry_name_eq` 会读过 query 的 NUL | 有界越界读，从 `callNamed` 可达——**已修** |
| `strParseInt` 溢出时返回截断的前缀 | 静默算错，与 oracle 不一致——**已修** |
| 生成的镜像不是构建依赖 | 重新生成它不会触发重编，于是出货了过期镜像——**已修** |
| 诊断版运行时会被部署进 runner 目录 | 桌面 release 可能绑定一个导出 `code_probe` 的运行时——**已修** |
| `verify_protection.ps1` 把 app 里的 stub 名字当 `info` 打印 | 掩码表只有在名字**不**同时出现在 `libapp.so` 里时才有意义——见下 |

共同点：**上面每一条都是"文档描述了设计意图，而代码没有实现它"。** 文字对计划的描述没错，对**当前状态**的描述错了。这也是为什么修复都配了会在行为回退时失败的检查，而不是配一句改好的注释——改好的注释同样"正确"，也同样没被验证。

有两条**没有修**，是诚实的剩余缺口：

- **stub 的名字仍然随 `libapp.so` 出货。** 运行时的名字表已掩码，审计也确认那里一个名字都没留下；但生成的 Dart stub 会把函数名传给 `Vmp.call(id, name, args)` 用于诊断，所以出货的 app 里带着同样那七个明文名字。也就是说掩码表抬高的是读**运行时**的成本，不是读 app 的成本。去掉那个参数对 stub 生成器是个小改动。
- **畸形镜像的处理完全没有差分覆盖。** 套件只跑那九个受保护函数；`strParseInt`、builder 系列 builtin、`abort` 以及各条错误路径没有任何受保护函数会调用——这正是上面两个 bug 一直没被发现的原因。它们是被一个"能构造任意容器"的 harness 找出来的，而把那个 harness 变成测试是下一步最值得做的事。

### 各层各自挡住了什么

每一层都对应一条具体的攻击路径，值得写清楚分别堵的是哪条——答不出这个问题的层，等于没做：

| 攻击方式 | 由什么挡住 | 强度 |
|---|---|---|
| **静态分析**出货二进制 | 逻辑编译成私有指令集、容器加密、函数名掩码化 | 强 |
| **直接改字节** | body 的 CRC + 认证 tag，在执行任何一条指令之前就校验 | 强 |
| **dump 指令仓库** | 用运行期熵派生的密钥加密，不写进任何头部，每次调用重抽 | 中 |
| **调用之间 dump** | 调用结束时元数据 body 被擦除、指令仓库也被擦除，模块关闭期间既没有明文也没有密文可找 | 强 |
| **在调用期间 dump** | 有上界——最多 `DVMP_CODE_SLOTS`（4）个已解码函数常驻，外加元数据；整条指令流永远不会全部常驻 | 中 |
| **从 Dart 侧够到逻辑** | 受保护函数体根本不在 AOT 快照里 | 强 |
| **把受保护函数当 oracle 调** | 在受保护源码里声明的逐函数调用策略，由运行时强制执行，超额时用独立状态码拒绝 | 弱，且只挡得住这种攻击的廉价版本 |
| **两个线程同时调用** | 进程级锁；模块和解释器都是单实例 | 强 |

这张表现在每一行都填上了，而这与第一版不同：原来有两行写的是"无"，那两行就是这套设计**诚实的边界**。边界本身没有移动——见下面关于常驻模型的那段——但它们从"敞开"变成了"有上界"。

**"调用之间 dump 找不到东西"是最近才成立的。** "解密 → 执行 → 擦除 → 重新加密"从一开始就写在文档里，而它是**假的**：重新封装是从一份**副本**构建容器、并且只擦除了那份副本，于是 `m->body` 把 canonical body（字符串表、常量池、描述符、已解码的指令流）留了整整一个进程生命周期。一次对抗性审计在本套件**全部通过**之后，从单个内存页里读出了受保护字母表字符串和 `add` 的解码字节码，而 `Vmp.secureBytesLive()` 在调用前后报告同一个数字。现在 seal 会擦除 body、open 会重建全部解析视图；`dvmp_module_body_residue()` 报告该缓冲区非零字节数（只报数量、不报内容），套件断言调用返回后它是 0。这条检查是原来那条做不到的：原来读的是 `unsealed` 标志，而它在缓冲区仍装满明文时**正确地**是 0。

**在调用期间 dump，不再能一次拿到整个程序。** 解码后的指令流不以整块形式常驻。`open` 先认证出货容器、把元数据（字符串表、常量池、描述符）解到 body 里，然后把指令流用 `code_key` 重新加密——每次 open 都重抽的运行期熵，不写进任何头部——存进一个与原始区域布局完全一致的仓库，并且**擦掉 body 里的那一份**。解释器每次只从仓库里物化**一个**函数到 4 个槽位中，而 `dvmp_code_ensure` 在每条指令取指时重新校验槽位身份，所以槽位冲突只会导致重新加载，永远不会给出错误答案。

本模块的实测值：9 个函数、958 字节指令流，任意时刻同时常驻最多 4 × 215 = 860 字节。绝对值不好看，因为模块本身很小——**有意义的是比例，而且它随函数个数增加而改善**，因为槽位数是常数。这一段写这么直白，是因为这个主张很容易被吹大：**它挡不住调试器。** 能暂停进程的攻击者可以每个函数暂停一次再拼回去，而拼装是机械劳动，因为常驻元数据里的描述符带着每个函数的偏移和长度。它改变的是：**一次**顺带的抓取——崩溃转储、被换出的页、被暂停的调试器、一张十六进制编辑器的截图——拿到的从"整个程序"变成"一个函数"。静态攻击者则完全不受影响，因为出货容器按设计就是可以离线解开的。

这条性质是靠**测量**而不是靠散文来守的，在 `app/test/vmp_e2e_test.dart` 里通过三个不含内容的计数：

- `Vmp.codeResidency()`——槽位数、当前占用槽位数、历史峰值、最大函数字节数、模块指令流总字节数。测试断言 `peak * largest < total`、`peak <= slots`，以及 `slots < 函数个数`（没有这一条，前一个上界就是空的）。App 测试会先调用全部受保护函数，所以这个上界是在缓存已经被填热之后测的，而不是在空缓存上测的。
- `Vmp.codeResidue()`——已解码槽位里的非零字节数、**封存那一刻** body 代码区里的非零字节数、以及指令仓库里的非零字节数。中间那个是最锋利的一条：封存是"指令流还躺在 body 里"这件事在调用之外**唯一可观测的时刻**，而上一版设计在那里会报出模块的整条指令长度。三个都必须为 0。
- `Vmp.decodedCodeProbe(id)`——和以前一样，模块封存期间拒绝服务。

这三条都做过反向验证。关掉 body 擦除后，套件以 `the body still held 559 bytes of instruction stream when the module sealed` 失败；把槽位数改成 16 后，套件以 `the runtime has 16 slots for 9 functions, so "not everything at once" is not actually a constraint` 失败。**一条从未被看到拒绝过任何东西的检查，只是一句 print。**

**指令仓库无法用磁盘上的东西解开。** 出货容器必须自带种子——离线分发模式决定了二进制要自带运行期材料，所以那个种子是公开的。仓库不用它：密钥每次 open 都从运行期熵重抽，不写进任何头部。`Vmp.sessionProbe()` 会把出货种子和**实际用过**的密钥与盐一起报出来，套件断言二者不等、且密钥每次调用都会轮换——因为这里的失效方式是**静默**的：如果仓库哪天改成用出货种子封装，每次调用依然会返回正确结果。

这一点值得说准，因为早先的措辞（"工作副本的 dump 无法离线攻击"）把它说大了。运行期密钥仓库真正买到的是：一次**局部**抓取——一个缓冲区、一页内存、一个交换文件、单个分配的崩溃转储——用磁盘上的任何东西都打不开。它挡不住**整进程**抓取：`code_key` 和 `code_salt` 与仓库在同一个地址空间里，谁读得到一个就必然读得到另一个。这一点对它所取代的那个工作容器同样成立——那个容器的 session key 和 nonce 也是一样常驻的。而**删掉那个容器本身就是这次改动的一部分**：一旦 `open` 开始擦除 body 的代码区，重新封装出来的容器就只能是用"指令流已被清零的 body"构建的，它的 CRC 和 tag 描述的是一个已经不存在的东西。它从来没有被解密过，也没有任何测试发现——这恰恰是本仓库反复踩到的那种**假不变量**的形状：一个从未实现的文档化锁、一次只覆盖了副本的文档化擦除。这个诱饵被删掉了，而不是留在那里。

**调用是进程级串行的。** 模块和解释器都是单实例，而 open/seal 会原地重写 body，所以两个线程同时进一个调用会互相破坏。Dart 的 isolate 是共享这个库的独立线程，`Isolate.run` 和 `compute` 都能从普通业务代码走到那个状态。头文件从一开始就宣称有 native lock，而**它根本不存在**；观测到的结果是错误答案、"module corrupt"、以及访问违例。现在 `dartvmp_call` 和 `dartvmp_init` 会取进程级锁，由 `tool/verify_concurrency.ps1` 验证——那是一个 C harness，用 8 个 OS 线程驱动公开 ABI，并把每个结果与单线程参考值对比。去掉锁之后它会报出数千个错误，所以这条检查是有牙齿的。

**以前每次调用都会泄漏一个描述符数组。** `parse_body_views` 每次 open 都会跑——这是必须的，因为 seal 会擦掉它解析的那个 body——而它用一个裸 `calloc` 分配描述符数组，从不释放上一个。于是每次受保护调用泄漏 `函数个数 × sizeof(DvmpFuncDesc)`。它躲过了三轮审计，原因值得记下来：这个数组**不在**受保护分配器上，所以 `Vmp.secureBytesLive()` 从来没统计过它，而那是套件里唯一一条泄漏形状的检查。并发 harness（3200 次调用）大约会涨 1 MB，没有人盯着看。现在这个数组只分配一次并复用，改到受保护分配器上，并且 `app/test/vmp_e2e_test.dart` 新增一条检查：跑 256 次调用，要求受保护字节数前后**完全相等**。反向验证方式是把"每次调用都分配"改回去：检查以 `the guarded allocator grew by 1048576 bytes over 256 calls, so the open path leaks 4096 bytes per call` 失败。

**oracle 现在有预算了，而这个预算就是策略本身。** 一个职责是对"猜测"回答是/否的受保护函数，本质就是一个校验器，循环调用它是成本最低的攻击：本机实测，一次无策略的受保护调用大约 20 万次/秒。现在 `protected/` 可以在函数旁边声明调用策略——

```dart
// @vmp guard:rate=4096/1000      // 每 1000 ms 最多 4096 次
// @vmp guard:once                // 整个进程最多一次
```

——编译器把它编进该函数的描述符，运行时在做任何工作之前强制执行，超额时用 `DARTVMP_ERR_TOO_MANY_CALLS = -20` 拒绝。它是**拒绝**，永远不会返回错误答案；`Vmp.resetCallPolicies()`（只在诊断构建里导出）让测试既能断言策略确实咬人、又能断言函数之后仍然算得对。默认是**没有策略**：guard 是关于"业务代码允许多久调一次"的明确表态，只有作者知道该填多少。

预算按**合法调用速率**来标定，而不是按攻击速率——这一点试了三次才对。`8/1024` 和后来的 `64/2048` 都是对着 oracle 选的，结果两次都低于本仓库自己的差分套件所达到的速率，于是两次都让**正确的调用方失败了**——而这正是本 README 第一条规则禁止的结果。现在出货策略是 `4096/1000`：实测天花板的 2%、大约是人手输密钥速率的 1000 倍、并且高于批量激活界面的需求。两条测试把它钉住：一条从 manifest 里读声明出来的预算来给自己定循环次数，而不是把数字重抄一遍；另一条在声明预算低于"512 次合法突发"这个已文档化的上界时失败。

它做不到的是拦住把 guard 补丁掉的人——进程是他们的。它拦住的是**完全不需要逆向**的那种攻击：把出货的库当成快速校验器来用。

### 明文到底在哪里

整套设计的核心主张是"逻辑不存在于 `libapp.so` 中"，APK 校验脚本守的就是这一条。但那是
关于**静态**暴露面的主张。**运行期**暴露面同样值得说清楚，因为它直接决定**哪些函数值得
保护**。

进程内解释器无法避免在运行期间产生明文；而这套架构里没有 `eval`/`exec` 的交接环节，所以
**正常情况下**逃出 VM 的明文只有一样东西：受保护函数的**返回值**跨过 FFI 的那一份。由此
得到一条判据：

> **留在 VM 内部的值受保护，跨 FFI 返回的值不受保护。**

拿 `protected/` 里的 9 个函数套一遍：

| 函数 | 返回 | 跨 FFI 的内容 | 值得保护吗 |
|---|---|---|---|
| `verifyLicense` | `bool` | 1 bit；`key`/`groups`/`expected`/`sum` 全程留在 VM | **值得** |
| `checkSum` | `int` | 输入本已是派生值，结果又过了 finaliser 混合并 `% 1048576` | **值得** |
| `selfTest` | `bool` | 1 bit | **值得** |
| `commandChecksum` | `int` | 64 位 FNV 哈希 | 部分 |
| `add`、`base32Index` | `int` | 答案本身，而答案不是秘密 | 有限 |
| `deviceToken`、`normalizeKey`、`makeLicenseKey` | `int`/`String` | **派生出来的产物本身** | 有限 |

最后一行是**结构性**结论，不是缺陷：一个"负责产出令牌"的函数必须把令牌交出去，所以把它
的函数体搬进 VM，对攻击者而言只是多了一次普通调用的成本。**VMP 真正划算的场景是"输入和
输出都不敏感、只有中间过程是秘密"的函数**——也就是许可校验这一类形状。

两条推论都已经在本仓库落实：

- 出货的 App 里不再有受保护函数的明文 Dart 副本。**差分 oracle 对攻击者的价值高于算法本
  身**，因为它把"还原"变成了逐位比对的是非题。`app/lib/main.dart` 里那份用于性能对比的
  AOT 基线现在在 `kReleaseMode` 下不可达，因此会被 tree-shaker 从快照里摇掉；
  `tool/verify_protection.ps1` 会在它重新出现在 APK 里时让构建失败。
- `Vmp.verifyImage()` 会把整个容器复制进 Dart 堆去查找明文探针，这是诊断手段，所以
  Demo 只在非 release 构建里调用它。

本节这套复核（按攻击路径分工、结构—词法绑定、明文窗口判据）与另一份解释器 VMP 方法论的
对照，包括其中**有意不适用**于本项目的机制，见
[docs/skill-review-lang-vmp-guide.md](docs/skill-review-lang-vmp-guide.md)。

### C 层：哪些受保护，哪些只是接好了线

上面所有内容保护的都是**字节码**。执行它的解释器是普通 AArch64，
`docs/skill-review-lang-vmp-guide.md` 一直把这一条列为唯一未补的缺口（L5"执行者保护"）：
把 `dvmp_module.c` 当机器码读的攻击者可以重新实现私有指令集，从而给字节码写一个反汇编器——
而字节码正是整套设计存在的意义。

做这件事的工具是 [VMPacker](https://github.com/bivex/VMPacker)（ARM64 ELF 虚拟化器）。
它已经在本机从源码构建起来（`tool/build_vmpacker.ps1`：用 NDK 的 clang/ld.lld/objcopy 编出 VM 解释器
stub——它 Makefile 里期待的 `aarch64-linux-gnu-` 其实并不需要——然后再编 Go 的 packer），
由 `tool/apply_vmpacker.ps1` 套用。**五个函数被虚拟化并在真机上验证通过——按数值验证，不是按"没崩"；
两个被检查拒绝，因为工具能翻译它们、而它们随后会让应用崩溃。** 逐目标的证据、出错地址、那个算错的
`CSEL` 和推理都在 [加强了什么](#加强了什么以及有意没做什么) 的第 1 项里；本节讲的是交接本身。

交接里大部分是检查，因为按名字找函数的工具**失败得很安静**：找不到匹配符号时它无事可做，而"无事可做"
和"成功"长得一模一样。下面每个分支都反向验证过——每一个都是在亲眼看到它要抓的失败之后写的：

| 分支 | 结果 |
|---|---|
| 工具不存在 | `-AllowMissing` 打印 `RESULT: NOT APPLIED` 退出 0；不加则抛错 |
| 输入是**已 strip** 的 `.so` | 拒绝：`has no symbol table, so VMPacker cannot find any function in it` |
| 输入是 **x86_64** 的库 | 拒绝：`is a Advanced Micro Devices X86-64 library, and VMPacker rewrites AArch64 only` |
| 目标名已不存在（被内联掉） | 拒绝，并指出要用 `-DDVMP_VMPACKER=ON` |
| 目标里有**调用**或读全局变量 | 拒绝，并报出指令和偏移：`+0x4428 bl 0x9624 <vmp_secure_alloc>` |
| 目标的辅助函数留在外面 | 拒绝：`these helpers exist as separate functions in …: op_tables` |
| 目标被编译器克隆出带后缀的副本 | 拒绝：`contains suffixed copies of its targets: unpermute_code.specialized.1`（真在交付物里出现过一次，反向验证用的就是那份产物） |
| 只翻译了**一部分** | 拒绝：`translated these targets only partially: … 64/70` |
| 工具退出 0 但**什么都没改** | 拒绝：逐个比对目标入口地址前后的字节 |
| 工具真的改了 | `RESULT: APPLIED`，12 字节跳板，导出 ABI 前后都是 9 个 |
| 库**跑不起来** | 拒绝：`tool/verify_device_run.ps1` 装上真机跑，出现崩溃记录就失败 |

四条实测结论决定了设计，每一条都是一个"构建全绿、库没保护"的陷阱：

1. **构建必须留一份未 strip 的副本，而且按 ABI 命名。** Gradle 的 release 打包会把 CMake 产物
   **原地** strip——`intermediates/cxx/…/obj/arm64-v8a/libdartvmp.so` 有时候有符号、有时候 `llvm-nm`
   直接说 "no symbols"，取决于最后跑的是哪个 task，所以读那个文件本质上是竞态。第一版解决办法用的是
   一个对所有 ABI 通用的文件名，结果 x86_64 那次构建赢了：名叫 arm64 的路径里躺着 x86_64，工具拒绝了它。
   现在每个 ABI 的副本是 `build/unstripped/libdartvmp.unstripped.<abi>.so`，而抓到那个错误的就是上面的
   机器类型检查。
2. **`noinline` 是承重的，而反方向的 `always_inline` 同样是承重的。** `-O2` 下那些小辅助函数没有独立
   存在，全被内联进调用方，所以 `DVMP_VMPACKER_TARGET` 给每个目标加 `noinline, used` 让它们找得到。
   反过来的情况更糟：被两个目标调用的 `static` 辅助函数会保留自己的函数体，而那个函数体正是跳板想藏的
   东西。`op_tables` 就是这样，`tool/vmpacker_targets.txt` 里的 `!op_tables` 就是不让它回来的检查。
3. **"构建期找得到、运行期调不到"在本工具链上表达不出来。** 三种测法：非 `static` 但 hidden
   可见性的函数（`dvmp_module`、`dvmp_vm_run`）最后仍是 local（`t`）；加
   `visibility("default")` 会变 global（`T`）**并且**进 `.dynsym`，也就是能被 `dlsym` 调用；
   再叠上钉住导出面的 version script，`local: *` 又把它打回 `t`——因为 `local: *` 重写的是整张
   符号表，不只是动态符号表。这是个二选一，本项目选**不导出**：导出的 `unpermute_code` 对攻击者
   是一件现成的工具，而 local 符号照样以本名躺在 `.symtab` 里，正是按名字读符号的工具要看的地方。
4. **带栈金丝雀的目标不是目标。** NDK 默认带 `-fstack-protector-strong`，而 VMPacker 的 VM 不复现读
   金丝雀的那次 TLS 访问，所以 `DVMP_VMPACKER_TARGET` 带上了 `no_stack_protector`。见第 1 项。

目标清单是设计的另一半，而它现在有**五**项而不是八项：

```
已虚拟化、真机验证通过    apply_keystream, keystream_seed, dvmp_body_tag,
                          permute_code, unpermute_code
拒绝：需要调用            dvmp_mask_keystream, code_store_build
有意不作为目标            dvmp_vm_run（指令循环）
                          dvmp_code_ensure（每条指令调一次）
```

第一行中间那三个是第二轮的工作：每一个都是从拒绝列里搬出来的，办法是把 VMPacker 处理不了的构造从
**我们自己的**源码里去掉——一次调用、一个 `adrp`、SIMD 寄存器流量，最后一个是不崩但**算错**的
`CSEL`。这份记录住在 `tool/vmpacker_targets.txt` 里，而上面第 1 项的那张表是给读者看的部分。

被 VMPacker 保护的函数跑在**第二台**解释器上，代价是按**调用**计的，而解释器循环正是唯一绝不能进去的
函数：那等于在每一次受保护调用的每一条字节码指令上套一层 VM 套 VM。上一轮的常驻改造正好让这个划分变干净：
每条指令的集合现在就只剩五个函数，其余都冷到虚拟化本来可以白拿（**不**包括 `dvmp_mask_keystream`：
它仍然是一次调用）。拦住 `dvmp_mask_keystream` 和 `code_store_build` 的是**正确性**，不是代价。

还要说清楚的是：**VMPacker 改写的是 ELF，所以对 Windows 完全不适用。** 桌面运行时是被链进
`dartvmp_demo.exe` 的 PE 镜像，那边的 C 层保持未虚拟化。这是只属于 Android 的加固步骤，所以 Windows
构建里这些函数全都是普通的 x86_64 代码，正是第 1 项量出来的"可读"状态。这就是 C 层的诚实状态：
Android 上五个（含指令流映射和容器标签），桌面上零个；而**解释器本身在两边都是可读的**。

### 发布加固

测试套件使用的诊断探针（`dartvmp_code_probe` 等）在发布构建中会被编译掉。Android 插
件传 `-DDVMP_DIAGNOSTICS=OFF`，使发布库的导出符号从 20 个降到 9 个已文档化的 ABI 函
数；`verify_protection.ps1` 会在探针符号残留时让构建失败。桌面测试库保持开启
（`tool/build_native.ps1`），因为那是 `flutter test` 唯一能触达解释器内部的途径。

导出面现在是**链接期事实**，而不再只是某个 CMake 预设的副产品：
`packages/dartvmp/src/vmp_exports.map.in` 按构建配置生成，作为 version script 交给链接器，
没列进去的一律在 DSO 内本地化。而且它会**大声失败**——Android 工具链带
`-Wl,--no-undefined-version`，而这个文件的第一版无条件列了那些诊断探针，在把它们编译掉的
release 构建里那就是一个链接**错误**。"必须按配置生成"就是这么发现的。

这个宏同时是**那些绝不能活到发布版的功能门**的开关。真正要紧的是反调试的后门：

```
DARTVMP_NO_ANTIDEBUG=1 ./app        # 以前可以用它关掉插桩检测
```

它原先只是一个运行期的 `getenv` 判断，于是整层反调试在 shell 里是可选的，变量名也能
在出货的 `.so` 里 grep 到。现在它被编译出任何**不带诊断探针**的构建，并且
`tool/verify_antidebug_gate.ps1` 会构建两种配置、断言前者的二进制里有这个名字、后者
没有——因为**"因为错误原因而通过"的门禁比没有门禁更糟**。发布构建也会被直接扫描这个
字符串，与明文探针一起。

由此得到一条通则，也是把这段写下来的原因：**能被一个环境变量关掉的保护不算保护；
只该在测试构建里存在的开关，就不该被编译进出货的二进制。**

---

## 三、快速开始

环境要求：Flutter 3.41+、带 NDK 的 Android SDK，以及（Windows 桌面端）带 C++ 工作负
载的 Visual Studio。

```bash
# 编译 + 测试 + 部署运行时 + 验证 —— 一条命令
powershell -ExecutionPolicy Bypass -File tool/test.ps1
powershell -ExecutionPolicy Bypass -File tool/test.ps1 -Release   # 额外出 APK 并做保护校验
```

或者分步执行：

```bash
# 1. 编译受保护源码，生成全部产物
dart run tool/build.dart                    # 随机种子，发布构建就该这样
dart run tool/build.dart --seed 0x1234      # 可复现

# 2. 看看编译出了什么
dart run tool/vmpc/bin/vmpc.dart disasm --seed 0x1234

# 3. 检查产物有无泄露
dart run tool/vmpc/bin/vmpc.dart check

# 4. 编译器测试
cd tool/vmpc && dart test                   # 33 个测试

# 5. 原生运行时 + App 测试
cd ../..
powershell -ExecutionPolicy Bypass -File tool/build_native.ps1
cd app
$env:DARTVMP_LIBRARY_PATH = "$PWD/build/native/dartvmp.dll"
flutter test                                # 22 个测试
Remove-Item Env:\DARTVMP_LIBRARY_PATH

# 6. 跑 Demo
flutter run -d windows

# 7. 出包并验证
flutter build apk --release --target-platform android-arm64
cd ..
powershell -ExecutionPolicy Bypass -File tool/verify_protection.ps1
```

### 为什么原生测试需要环境变量

`flutter test` 会自己构建一个测试宿主可执行文件，而 Flutter 是把桌面端运行时**静态
链接进 runner** 的，所以测试宿主里没有它，必须从磁盘加载这个库。

把库直接扔在测试旁边并不可靠：Flutter 工具会截断它认为是构建产物的包根目录文件，实测
产生过一个 **0 字节的 `app/dartvmp.dll`**，结果是所有原生测试报「skipped」而不是失败。
部署到 `app/build/native` 并用 `DARTVMP_LIBRARY_PATH` 指过去才是确定性的做法。

不设这个变量时，原生测试组会**明确跳过**而不是空跑通过，所以 CI 不可能把「运行时缺
失」误读成「运行时验证通过」。

---

## 四、编写受保护代码

给函数加上 `// @vmp` 标记，它就会被编译进模块。文件放在 `protected/` 下，**永远不会被
App 导入**。

**那行注释就是全部的"选择机制"。** 任何地方都不需要你输入一张函数名清单：编译器去读受保护的
源文件，每一个 `// @vmp` 标记变成一个编译后的函数，而没有标记的声明留在应用里（`vmpc check`
会把它们列出来，所以"看起来受保护其实没有"不可能悄无声息）。所以"是不是要读 Dart 源码、再把
要保护的函数名输进去"的答案是：标记要在源码里写，函数名不用输——你在函数写的地方打标记，
告诉工具的是**读哪些文件**：

```powershell
dart run tool/build.dart                                  # 默认 protected/licensing.dart + protected/keys.dart
dart run tool/build.dart --source protected/a.dart,protected/b.dart
```

标记后面还可以带调用策略，这是对"导出的校验器就是任何能调用它的人的验证器"唯一在本地成立的答案：

```dart
// @vmp guard:rate=4096/1000     每秒最多 4096 次，超过就拒绝
// @vmp guard:once                每进程只允许一次
```

被拒绝的调用返回带 `DARTVMP_ERR_TOO_MANY_CALLS` 的 `DartVmpException`，**永远不会返回错误答案**；
语法在哪里解析和校验见 `tool/vmpc/lib/src/dart_source.dart`——写错的 guard 是构建错误，不是静默默认值。

```dart
// @vmp
bool verifyLicense(String rawKey) {
  String key = normalizeKey(rawKey);
  if (strLen(key) != 16) {
    return false;
  }
  String groups = strSub(key, 0, 15);
  int expected = base32Index(strAt(key, 15));
  return expected >= 0 && checkSum(groups) % 32 == expected;
}
```

### 支持的语法子集

因为解释器是刻意做小的，编译器只接受 Dart 的一个**子集**，凡是无法降级的写法都会**带
行号报错**——它绝不会静默丢弃函数体。

**支持** —— `int`、`String`、`bool`、`List`、`Map`；`if`/`else`、`while`、C 风格
`for`、`for-in`、`break`、`continue`、`return`；`+ - * / % ~ & | ^ << >>`、比较运算、
`?:`、`&&`、`||`；`x++`/`x--`；`+=` 等复合赋值；调用其他受保护函数；`const` 声明；
`import` 另一个受保护文件。

**内置函数** —— `strLen`、`strAt`、`strCode`、`strSub`、`strIndexOf`、`strContains`、
`strToUpper`、`strToLower`、`strParseInt`、`intToStr`、`hash`、`listLen`、`listAt`、
`mapGet`、`abort`。

**不支持** —— 闭包、类、泛型（`List<int>` → 请写 `List`）、`async`/`await`、生成器、
字符串插值、对 `List` 元素赋值、全局变量、package 导入。

其中有两条值得单独说明，它们是真花了调试时间才搞对的，代码里也在实现处标注了：

- **Dart 的 `%` 是欧几里得取模**——结果取**除数**的符号，所以 `-11 % 32 == 21`，而 C
  给的是 `-11`。解释器对此做了修正；没有这个修正，一个密钥派生循环会静默产出错误的字
  符。
- **Dart 的 `>>` 是算术右移**，而 C 对 `uint64_t` 的 `>>` 是逻辑右移。凡是两种语言要对
  同一段字节做哈希的地方，Dart 侧用 `>>>`、C 侧用 `>>`，并由
  `image_contract_test.dart` 把这种一致性钉死。

### 性能

解释执行比 AOT 机器码慢很多。Demo 的性能卡片会给出一个 512 轮密钥派生函数的倍率。受保
护函数只应放在**低频、高价值**的路径上——激活码校验、密钥派生、签名验证。**绝对不要**
放进渲染循环或逐帧回调。

### 决定"保护什么"的本地 UI

`tool/ui/` 是一个单页 Web UI，底层就是同一套 CLI 入口，用来替代原本只能手工编辑的那一步：

```powershell
python tool\ui\serve.py            # http://127.0.0.1:8777，会自动打开浏览器
```

它列出 `protected/` 下所有顶层函数、标出哪些已经带 `// @vmp`，让你勾选/取消并选择 guard，
然后**先给 diff，二次确认之后才写**。写入路径**只可能碰 `// @vmp` 标记行**，而且这是被检查的性质
而不是承诺：把所有标记行去掉后，改写前后必须逐字节相同；改写后的文本会被重新解析、逐项复核请求的
状态；页面带来的 `sha256` 过期时返回 409；会话内第一次修改某文件会先备份成 `<file>.bak`；写入本身
是原子的 `os.replace`。页面上还有 `vmpc check`、`verify_descriptors.py`、`walk_bytecode.py` 和
（可选）`verify_crypto.ps1` 的按钮。

它只用标准库 Python，只监听 `127.0.0.1`，**没有任何认证**——能访问这个端口的东西就能改本仓库的标记行，
所以不要绑到公网接口，也不要放在代理后面。它有意不跑 `tool/test.ps1`；API 和限制见 `tool/ui/README.md`。

---

## 挑战赛：把 flag 找出来

本构建可以作为一个 CTF 靶子发布：应用只在你给出受保护代码期望的那个 key 时才吐出 flag。
它存在的意义是把「这东西到底有多难」从一个形容词变成一个数字。完整规则、等级划分和提交格式见
[docs/CHALLENGE.md](docs/CHALLENGE.md)。

有三点写在这里而不是那里，因为它们是关于**本项目**的主张，不是关于挑战的：

- **flag 不是容器里的字符串常量。** `module_seal_locked` 会在两次调用之间把整个 body 擦掉，
  所以一个明文常量会被「应用在做任何事时」抓到的内存 dump 读走——那是五分钟的解法。现在的做法是
  把 flag 按「由 key 逐字符派生的偏移」旋转存储，因此它的明文只在**正确的 key 被接受之后**才存在。
- **预期解法是静态那条路**，也就是本 README「诚实的局限」里写的那条链：读运行时 → 解静态镜像 →
  剥容器密码 → 从 `unpermute_code` 恢复置换 → 读 `dvmp_vm.c` 得到 ISA 语义 → 重建 key 派生。
  按项目自己的估计，大约一到两天的逆向工作量。
- **把校验 patch 掉是可行的，并且被单独计为一个等级。** 对任何进程内保护来说，最便宜的攻击都是绕过去
  而不是读懂它。`dvmp_integrity.c` 能发现这类攻击的常见形状，但**有意不去阻止**它；挑战帖里直接写明
  这一点，而不是假装绕过不存在。

仓库里带有参考 flag（否则应用没法构建和测试）；**对外发布的靶子用的是另一个**——
发布前的检查清单同样在 [docs/CHALLENGE.md](docs/CHALLENGE.md)。

## 五、工程结构

```
protected/                     受保护源码 —— 永不被 App 导入
docs/                          防护边界分析与方法论对照
tool/vmpc/                     编译器
  lib/src/lexer.dart           受限 Dart 词法分析
  lib/src/parser.dart          递归下降语法分析
  lib/src/emitter.dart         AST → 私有字节码
  lib/src/packer.dart          opcode 置换 + 流密码 + 认证标签
  lib/src/c_emitter.dart       生成 C 头文件（掩码镜像）
  lib/src/evict.dart           从 App 源码中剔除受保护函数体
  bin/vmpc.dart                CLI：build / disasm / check
tool/build.dart                构建入口
tool/test.ps1                  一键构建 + 全量测试
tool/build_native.ps1          把运行时构建成可加载库（供桌面端测试）
tool/verify_protection.ps1     扫描发布产物查泄露
tool/verify_image.py           证明静态镜像确实被掩码
tool/verify_antidebug_gate.ps1 证明发布构建没有后门开关
tool/verify_concurrency.ps1    用 8 个线程驱动 ABI（会编译它的 harness）
tool/concurrency_harness.c     上面那个脚本编译运行的 C harness
tool/capture_desktop_run.ps1   检查 runner 是否链入运行时，然后启动并截图
                               （`-CheckOnly` 供 CI 使用）
tool/apply_vmpacker.ps1        把 C 层交给 VMPacker，并证明它确实做了
tool/vmpacker_targets.txt      虚拟化目标、每个目标的真机结果、以及被覆盖面检查拒绝的段
tool/verify_device_run.ps1     把构建好的 APK 装到真机上跑，崩了就失败
tool/build_vmpacker.ps1        从源码构建 VMPacker（NDK clang + Go）
tool/repack_apk.ps1            替换 APK 里的库、对齐、重新签名
tool/repack_apk.py             真正的 zip 重建（`--check-only` 校验原生库的存储方式）
tool/recover_from_shipped.py   掩码密钥攻击，`--selftest` 是它的正向对照
tool/recover_opcodes.py        opcode 映射攻击，同样两个方向都跑
tool/ui/serve.py               选择"保护什么"的本地 UI（仅标准库）
tool/walk_bytecode.py          独立解码容器、校验 CRC 与 tag、并逐函数反汇编
                               （`--tamper` 可反向自证这两条检查）
tool/verify_descriptors.py     按偏移独立解出每个描述符字段
tool/audit_operands.py         检查每条指令的操作数读取都有边界检查
tool/list_symbols.py           列出共享库导出的 ABI
build/unstripped/              构建保留的按 ABI 命名的未 strip 副本，因为 Gradle 会原地
                               strip 掉 CMake 产物
packages/dartvmp/              运行时
  lib/dartvmp.dart             公开 Dart API
  lib/src/wire.dart            FFI 线格式编解码
  src/dvmp_vm.c                解释器
  src/dvmp_module.c            容器加载 / 解密 / 指令仓库 / 密封 / 解封
  src/dvmp_sha256.c            SHA-256 及建在其上的掩码密钥流
  src/dvmp_host.c              23 个内置函数的主机表
  src/dvmp_value.c             Arena、堆对象、线格式编解码
  src/dvmp_secure.c            受保护内存（用完即擦）
  src/dvmp_antidebug.c         反调试探测（默认关闭）
  src/dvmp_vmpacker.h          交接面，以及每一条属性为什么在那里
app/                           Flutter Demo
  lib/main.dart                UI：调用、性能基准、保护证据
  lib/generated/               生成的桩函数（勿手改）
  test/                        对拍测试与保护测试
```

### 容器格式

由 `tool/vmpc/lib/src/packer.dart` 与 `packages/dartvmp/src/dvmp_module.c` **共同定义**，
并由 `image_contract_test.dart` 钉死：

```
crc       = crc32(canonical body)        编译器产出内容的完整性
permuted  = permute(body, seed)          私有指令集
tag       = fnv1a(permuted ‖ seed')      落盘字节的真实性
stored    = cipher(permuted, seed)       机密性
container = header(seed, crc, …) ‖ stored ‖ tag
```

CRC 覆盖**规范化（canonical）**body，所以运行时只有在**先解密、再解置换**之后才能满足
它——这使它成为对三层保护的端到端校验。tag 覆盖**置换后、加密前**的 body，也就是真正
写进磁盘的那些字节，因此被篡改的镜像在第一条 opcode 执行前就会被拒绝。

这两条在 `tool/walk_bytecode.py` 里有**独立复现**：它从出货镜像重算 canonical CRC 和
tag，任何一条对不上就直接让整次运行失败。加 `--tamper` 参数它会先翻转一个密文字节，于是
这两条检查能被**看到**确实会拒绝——一条从未被观察到失败过的检查，只是一句 print。

描述符记录是 32 字节，并且**按名字读写、从不写字面量**：这条记录在几轮修订里先后是 24、
26、28、32 字节，而每一次改动都至少漏掉过一处仍然用着旧数字的地方。症状从来不是"描述符
错位"，而是三层之外的"代码区长度为 0"或者"body CRC 不匹配"。现在有两个 reserved 字段，
运行时和两个分析工具都断言它们为 0，把这一整类错误变成第一次 open 就硬失败：

```
[0..4)   name_off          [4..8)   name_len
[8]      guard_mode        [9]      reserved (0)
[10..12) guard_budget      [12..14) guard_window_ms
[14..16) arity             [16..18) locals
[18..20) max_stack         [20..22) slot_base
[22..24) reserved2 (0)     [24..28) code_len
[28..32) code_off
```

---

## 六、诚实的局限

这是一套可用的保护系统，但不是安全保证。特别说明以下几点：

- **解释器本身可以被直接攻击。** 愿意逆向 C 代码的攻击者能读到 VM 依赖的一切。私有指令
  集抬高的是读懂**逻辑**的成本，它并不能让实现变得不可篡改。容器的 CRC 与认证 tag 挡的是
  改字节，不是改解释器。
- **Dart 侧调试器能看到明文，且无法从 C 层阻止。** DevTools / VM Service 调试器观察的是
  Dart 堆，而受保护函数的返回值**必然**落在那个堆上。三种情况要分开说：**设备级**调试器
  （用 `gdb`/`lldb` 挂 `.so`）看到的是解释器的数组，那部分可以重新封装、可以部分擦除；
  **Dart** 调试器看到的是调用结果，擦不掉；而**在调用窗口内**挂上的调试器能看到解密后的
  工作镜像。`dvmp_antidebug.c` 针对的是廉价攻击（`ptrace`、Frida、`frida-server` 端口），
  且**默认关闭**；它只是一道减速带，里面每个特征码都会过期。
- **种子就在容器头部。** 离线分发模式决定了必须如此：二进制自带运行期材料，这是设计取
  舍。SplitMix64 的混合方式、掩码派生算法、以及 opcode 置换的构造方式，同样都随
  `libdartvmp.so` 出货，所以有耐心的攻击者可以自己写一个独立解密器——
  `tool/verify_image.py` 就是这件事的可用示范。第 7 项改变的是置换不再是**一个可以搜索的参数**；
  它没有改变"构造就在那里"这个事实。这些层买到的是"**没有一个短秘密可以被直接抠出来**"；
  它们**没有**买到"愿意重新实现整套方案的人也无法破解"。C 层同理，而且更直白：解释器本身
  仍然是可读的 AArch64（见上面的第 1 项）。
- **一次 dump 能抓到整个调用。** 这一条**已经修掉了**，保留在这里是为了记录它曾经的样子：分块惰性解密现在是**已实现并已验证**的——`open` 把指令流重新加密进一个运行期密钥的仓库，解释器每次只物化一个函数。见上面"在调用期间 dump"那段，以及它诚实的边界（挡不住调试器，只把单次抓取的价值从一个程序降到一个函数）。
- **函数名表已掩码，但派生方式随二进制出货。** 生成的 `kDvmpEntries[]` 以前把函数名当字符串字面量带着，等于在 `.rodata` 里放了一份**可 grep 的保护面清单**——直接指出哪些函数值得攻击，还顺带暗示算法族（`verifyLicense` 意味着比较，`checkSum` 意味着哈希）。现在名字以掩码形式存储、查找时逐字节解出，所以出货库里没有这份清单，也不存在完整明文的函数名驻留。但派生方式在二进制里，愿意逆向运行时的攻击者仍能还原——这抬高的是成本，不是让名字变成秘密。
- **单次 dump 会抓到整个解密后的 body。** 这一条**也已经修掉了**，同样保留是为了记录。原文如下："这套架构在调用开始时把 body 解密进一块受保护缓冲区、调用返回时擦除，所以明文窗口是"一次调用"而不是"一条指令"。要继续收窄，就得按分块解密指令流、并在执行离开每块时立刻重新加密——本轮**尝试过但回退了**：三代实现各自把一种静默的状态 bug 换成了另一种（一个被两个调用方以相反意图共用的编解码函数、一个"是否明文"模块级标志导致第一块之后的每块都被跳过、一个被翻译了两次的区域偏移），而三者暴露出来的症状**都是同一句误导性的"chunk failed its tag"**。" 这三代失败的共同防线现在写在代码里：`dvmp_code_ensure` 记录槽位持有的是**哪个函数**并在每次取指时重新校验，所以槽位冲突只会导致重新加载、永远不会给出错误答案——**正确性不依赖缓存命中**。当年那个"`code` 指针在取指处是函数基址、在操作数读取处被当成当前指令"的根因（第一次 `load` 读出 slot 2850 而不是 0）仍然由 `tool/walk_bytecode.py` 守着：它独立解码容器并反汇编，是在解释器自身的诊断已经指错了三层之后最终定位问题的手段。
- **Arena 是按调用整体释放的，不是增量回收。** 受保护代码不会泄漏内存，但病态的分配循环
  会撞到预算并报错，而不是反复抖动。`dvmp_arena_free` 是**有意的空实现**（代码里有说明）。
- **只支持 Android 和 Windows。** 这两个平台有真实的插件目录；`ios`、`linux`、`macos` 曾经
  被列在 `pubspec.yaml` 里却没有对应目录，等于在宣传不存在的支持，现在已经删掉。
  `openRuntimeLibrary` 里的分支保留着，加一个平台就是加一个目录。
- **Windows 是最特殊的一条加载路径。** 桌面 runner 把运行时静态链进可执行文件，所以 Dart 侧
  必须走 `DynamicLibrary.executable()`；Android 正好相反，走 `open('libdartvmp.so')`。这两条
  路径**都**只有真跑才覆盖得到——测试宿主 `flutter_tester.exe` 自己不含运行时，只能通过
  `DARTVMP_LIBRARY_PATH` 加载外部 DLL，而那正是出货桌面应用不会走的路径。
- **没有发布 32 位 ARM。** `abiFilters` 只保留了 `arm64-v8a` 和 `x86_64`；对一个安全组件
  来说，发布未经测试的 ABI 比不发布更糟。
- **反调试、APK 签名校验、C 层的 OLLVM 加固不在本仓库范围内**——它们与 Dart 侧的 VMP 是
  正交的，更适合由专门的原生加固方案提供。
- **函数名可以被逆向运行时还原。** 生成的 `kDvmpEntries[]` 不再以字面量携带函数名——它们以掩码形式出货、按需解出（见上面的说明）——所以出货二进制里没有可读的保护面地图。掩码派生方式在二进制里，所以这抬高的是"找到那张地图"的成本，而不是把它藏起来。但**桩函数声明名**仍然留在 `libapp.so` 里：业务代码写的是 `verifyLicense(...)`，AOT 快照必须保留这个名字才能链接。这是"不改变调用点"这条硬约束的直接代价，`tool/verify_protection.ps1` 现在把"哪些名字在、以及为什么在"逐条列出来：只有桩声明名算过关，其他任何名字出现都直接判 LEAK。
- **oracle 被限流了，但限流可以被补丁掉。** 调用策略在运行时的 C 代码里执行，补丁掉它就是改几个字节的事。它挡住的是**不需要任何逆向**的那种用法（拿出货的库当快速校验器），挡不住愿意读反汇编的人。
- **常驻明文有上界，但上界不是零。** 调用期间最多 4 个已解码函数 + 元数据（字符串表、常量池、描述符）在内存里。元数据**必须**常驻——`push_k`/`push_s` 每条指令都可能读它——所以字符串字面量和整数常量池是一次 dump 能拿到的部分。指令流才是大头，也才是被收窄的那部分。
- **一次全进程 dump 仍然能拿到一切。** 运行期密钥（`code_key`/`code_salt`）与指令仓库在同一个地址空间。运行期加密买到的是"局部抓取打不开"，不是"抓不到"。见上面关于常驻模型那段。

---

## 七、踩过的坑（值得一读）

系统现在全绿，但走到这里暴露出了一类值得知道的 bug，如果你要扩展这套东西：

> **Dart 和 C 在整数语义上的分歧，在你数据被搞坏之前是完全看不见的。**

下面每一条都是**通过与参考实现对拍发现的，不是靠读代码看出来的**：

| 差异 | 症状 |
|---|---|
| Dart `>>` 算术右移，C 对 `uint64_t` 逻辑右移 | 密钥流岔开 → body CRC 不匹配 |
| Dart `%` 欧几里得，C 截断取余 | 从第 2 轮起密钥字符全错 |
| 对**负** Dart int 做 64 位 hex 格式化 | 掩码 key 符号位错 → 魔数错 |
| `x++` 若不降级成 `x = x + 1` 就没有 store | 死循环 → Arena 耗尽 |
| 字节码描述符缓存了裸指针 | body 被重写后执行到陈旧代码 |
| 指针被存进 `uint32_t` 字段 | 每次字符串拼接都访问违例 |

教训不是「要小心」，而是：**跨语言的数据契约需要一个从两端同时钉住它的测试。**
`image_contract_test.dart` 用**运行时自己的算法**去解生成的 C 头文件里的镜像，再与
packer 产出的容器比对——单这一个测试就能抓住上面六条里的四条。

### 一次把本文件改坏的文档编辑

值得记下来，因为它就是同一条教训往外推一层——**改散文是没有测试的**——而且它恰好发生在本次会话的这份
README 上。

当时用了一个 shell 惯用法来替换文件里的几个字符串：`Get-Content -Raw` 之后再
`Set-Content -Encoding utf8`。在 CP936 控制台上，这会把文件的 UTF-8 字节按 CP936 解码再写回，于是每个
非 ASCII 字符都变成一个以 `?` 结尾的残迹（em dash 变成 `e2 80 3f`），**而且它后面那个字节被一起吃掉**。
它跑了两次，损害因此叠加：217 处、ASCII 图变成占位符、文件不再是合法 UTF-8。

三件事让它比一个错别字严重得多：

- **它是不可逆的。** 尾字节已经没了，所以变换无法反演。那些 em dash、箭头和制表符是靠**在已知字符串上
  模拟这次往返**恢复出来的：把损害按每个标记**后面**的字节分组（标记后面跟字母，说明"破折号后面的空格
  被吃掉了"），然后手工修掉约 24 处不适用这条规则的地方——以及它引入的一个真实 bug：容器格式里的 `‖`
  与 em dash 共用同一个受损标记，被静默替换成了破折号。恢复脚本留在 `build/` 里而不是删掉，因为**方法**
  才是有用的那部分。
- **什么都没失败。** 构建全绿、所有测试通过，第一个症状只是一个工具拒绝打开这个文件。
- **它发生在没有覆盖的地方。** 本仓库里其他每样产物都有检查，散文没有。

所以修法是一个检查，也就是本文件反复讲的那种模式：`tool/check_encoding.py` 走一遍仓库里的文本文件，
要求每个都能按 UTF-8 解码，不满足时报出字节偏移；`tool/test.ps1` 会跑它。它第一次运行就找出了第二个
文件（`app/build_log.txt`，一份 GBK 编码的过期编译日志）——这正是检查的用处。以后编辑的规则写在那个脚本
的文档字符串里：用会写 UTF-8 的工具，**永远不要**对含非 ASCII 的文件做 `Get-Content`/`Set-Content` 往返。
