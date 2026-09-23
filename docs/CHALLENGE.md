# FDartVMP 挑战赛 · 第一季：把 flag 从「不存在的代码」里拿出来

> 作者：haothtrteen · 联系：2557976190@qq.com
> 靶子：`FDartVMP-challenge.apk`（arm64-v8a，Android 8.0+）
> 规则、提交方式、评分见文末。**先读规则再动手**——有一条会让你少走两小时弯路。

---

## 一、这个靶子是什么

一个 Flutter 应用，界面上有一个输入框和一颗按钮。输入正确的 key，它会给你 flag；输错，它只会冷漠地告诉你「不对」。

听起来平平无奇。**不平凡的地方在于：那个判断逻辑，不在这个 APK 的 Dart 代码里。**

具体点说：

- 你 `strings` 这个 APK，找不到 flag，也找不到 key 的推导过程；
- 你用 [Blutter](https://github.com/worawit/blutter)（Flutter 逆向的标准开局）把 `libapp.so` 的 AOT 快照完整还原出来，会看到那几个「受保护函数」只是几行 FFI 打包代码——把参数装进缓冲区、按一个数字 id 调进 native——**128 字节的搬运工，没有一行算法**；
- 真正的逻辑被编译成了一套私有字节码，加密后塞进了 `libdartvmp.so`，由里面那台私有解释器执行。**它只在你按下按钮的那一瞬间以明文存在。**

所以这不是一道「找字符串」题，而是一道「**证明你能把不存在于 AOT 里的逻辑拿出来**」的题。

## 二、你能拿到的公开信息

- `FDartVMP-challenge.apk`（就是它，别的什么都不给）
- 本仓库的源码（`protected/challenge.dart` 里有 flag 与推导代码，见下方「规则」第 4 条）

界面上的提示只有一句，写的是 `KDF("f-dartvmp", 7)`——`KDF` 就是仓库里的
`makeLicenseKey`，只是 release 界面上不能出现受保护函数的名字（有一条门禁盯着这个）。

flag 长得像 `FDartVMP{...}`，但**它的明文在容器里是「按 key 派生的偏移旋转过的」**，所以「随便 dump 一下内存」这一步我已经替你堵上了——你 dump 到的是乱码，除非你手里已经有正确的 key。

## 三、五个等级：你打到哪一层，就在提交里写哪一层

我把它设计成阶梯，因为这道题的乐趣不在「能不能」，在「你从哪条路进去」。**每一层都算分，也都值得写出来。**

| 等级 | 你要做到什么 | 大约要多久 | 备注 |
|---|---|---|---|
| **L0** | 在 APK 里 `strings` 直接找到 flag | 你找不到的 | 找不到才是正常的，找到说明我该回去重修 |
| **L1** | 用 Blutter 还原 `libapp.so`，找到受保护函数的算法 | 也找不到 | 这一段是真的不在里面 |
| **L2** | **Patch / hook 掉那个判断**，让 UI 直接吐 flag | 10 分钟～1 小时 | 见规则第 4 条：**光明正大，算分**，而且我会告诉你为什么防不住 |
| **L3** | 解出正确的 key（重建 keygen），正常输入拿到 flag | 半天～两天 | 这是设计上的「预期解法」，也是我最想看的提交 |
| **L4** | 在调用期间 dump 进程内存，把解密后的指令流/字符串表捞出来 | 看你的调试器水平 | 这一层是「运行期 vs 静态」的分水岭，欢迎写清楚你 dump 到了什么 |

**L2 为什么单独列出来：** 因为它是最便宜的攻击，而我这个人拒绝把它藏起来不说。DartVMP 这一版**会在 `init` 时扫描九个 ABI 入口点的头几条指令**，看看有没有人往上写了跳转（Frida Interceptor、Dobby、手工 patch 都是这个形状），检测到就把已解码函数的缓存从 4 个槽位收窄到 1 个——**但它不改变任何答案，也不拒绝启动**（理由：一个会弄坏应用的保护层，比没有保护层更糟）。所以你放心 patch，我们只是会知道。

至于「我 patch 了但它还是对的」这种情况不会发生——它会照样给你 flag，因为 **patch 走的是绕过，不是破解**。提交时请如实写「L2：patch」，我会给你记 L2 的分，而不是假装你没解出来。

## 四、规则

1. **只允许静态分析与本机运行**。你可以反汇编、反编译、调试、Frida、dump 内存、patch、重打包、自己写工具。**禁止**：把 APK 上传到任何在线沙箱、请求别人帮忙跑、或者对我进行社工（我虽然人很好骗，但这是技术比赛）。
2. **允许 patch，禁止「伪造界面」**。改判断逻辑、跳过检查、hook 返回值——都行。但直接改 UI 让它显示一句你自己编的假 flag 不算：flag 必须是**你从这个二进制里真实取出来的那个**。判别方法：flag 的正文只有我知道，我会核对。
3. **不允许修改 / 重编译靶子后「证明」它可破**。你可以改，但结论必须来自原始 APK。
4. **关于源码**：本仓库 `protected/challenge.dart` 里有 flag 和完整推导逻辑——**因为它是这个项目的演示代码，不是秘密**。但公开发布的 APK **用的是另一个 flag**（发布前我会改掉并重新推导）。所以「读仓库拿 flag」这条路只在你本地构建时有效，对靶子无效。请把靶子当成唯一的真相来源。
5. 如果你的解法**只对某台设备/某个 Android 版本成立**，请在提交里写明——这仍然是有效发现。

## 五、提交格式

发到 **2557976190@qq.com**，标题 `[FDartVMP] L<等级> <你的 ID>`，正文请包含：

```
等级：L2 / L3 / L4
flag：FDartVMP{...}
key：（如果解出来了）
方法：一段话说清你怎么做到的，用什么工具
耗时：大概
卡在哪：如果你没打通，卡在哪一步（这个我也想知道）
```

**我最想要的其实不是 flag，是「卡在哪」和「你第一分钟想到了什么」。** 这两样对我改进这东西的价值，比 flag 本身高一个数量级。

## 六、预期难度，和我的诚实预告

**我预计 L3 会被解出来。** 这个项目自己的文档里写得很清楚：所有解密所需的材料都必须随二进制出货（离线可用的前提），所以**静态还原是成本问题，不是可能性问题**。理论路径是：

```
读 libdartvmp.so 拿到掩码密钥 → 解静态镜像 → 剥容器密码（seed 就在容器头部）
→ 读 unpermute_code 重建 opcode 置换 → 读 dvmp_vm.c 得到 ISA 语义
→ 反汇编字节码 → 重建 makeLicenseKey → 得到 key → 输进去拿 flag
```

我自己的 README 里对这个链路的估计是「一个熟练逆向工程师一两天」。**如果你两天内打通了，那是预期之内；如果你一小时打通了，请务必写清楚你是怎么绕过其中某一步的——那个我特别想知道。** 如果你一周没通，也欢迎写「我卡在 X」，因为那说明我把某一步做得比我自己以为的更难，这对我是好消息（对你可能是坏消息，抱歉）。

**另外我保证不在比赛期间偷偷改靶子。** 要升级我会另开一季，并且写清楚改了什么。

## 七、为什么做这个

这个项目叫 FDartVMP，是一个 Flutter 的源码级虚拟机保护系统。它现在能保证的事情是：**受保护逻辑不出现在 `libapp.so` 里**，这一点 Blutter 帮我验证过（它把我那几个函数还原成了 128 字节的搬运工，而同一份快照里 `wire.dart` 的数组边界检查倒是还原得很漂亮——工具没问题，是那些函数里真的没东西）。

它**不能**保证的事情，我在 README 的「诚实的局限」一节里写全了：解释器本身仍是可读的 AArch64，密钥与派生方式必须随货发出，一次调用期间的内存 dump 能看到那一个函数，patch 掉校验永远是最便宜的路。

所以这个挑战的目的不是「证明它不可破」——那是自欺欺人。目的是**把「有多难」从一个形容词变成一个可以测的数字**。你花的每一个小时，都是在帮我测这个数字。

来吧。把 flag 拿给我看，顺便告诉我你从哪儿进去的。

---

*FDartVMP 采用双许可：开源使用 AGPL-3.0-or-later，闭源产品需商用许可（联系方式同上）。细节见 [LICENSING.md](../LICENSING.md)。*

## 八、发布检查清单（给未来的我）

公开一季之前，按顺序做完这些，别跳步：

1. **换 flag**：改 `protected/challenge.dart` 里的 `kFlag` 常量与 `kFlagCipher` 的推导来源。
   `kFlagCipher` 不是手写的，而是由 `app/test/tool_challenge_cipher_test.dart` 推导出来的：
   改掉该文件里的 `kFlag`，在 `app/` 下跑 `flutter test test/tool_challenge_cipher_test.dart`，
   把打印出来的 `CIPHER=` 粘回 `protected/challenge.dart`。**仓库里的那份 flag 与发布靶子必须不同**，
   否则「读 GitHub」就是最短解法。
2. **重建全部产物**：`dart run tool/build.dart`（12 个函数 → 生成容器、桩、oracle、manifest）。
3. **构建混淆后的 release APK**：`flutter build apk --release --target-platform android-arm64 --obfuscate --split-debug-info=build/symbols`，
   并**归档 `build/symbols`**（否则崩溃栈不可读）。
4. **跑门禁**：`python tool/verify_protection.ps1`。必须看到：
   - `no protected algorithm data in the AOT snapshot`
   - `no protected function name appears in the AOT snapshot`
   - `the release snapshot describes nothing about the mechanism`
   如果 flag 或 `revealFlag` / `makeLicenseKey` 之类出现在 APK 里，这一步会拒绝，别绕过它。
5. **（可选，Android）C 层虚拟化**：`tool/apply_vmpacker.ps1` → `tool/repack_apk.ps1`，
   然后**必须** `tool/verify_device_run.ps1` 真机跑一遍。本轮实测：七个目标里只有两个能活，
   另外五个会让应用启动即崩——不做这一步就发出去，等于发了一个打不开的靶子。
6. **自测一次「预期解法」**：在真机上输入正确 key，确认 flag 显示；再故意输错 10 次，
   确认第 9 次开始出现「call policy refused」而不是错误答案。
7. **最后**：`tool/test.ps1 -Release` 全绿，然后把 APK 和挑战帖一起发出去。
   `docs/CHALLENGE.md` 里贴上 APK 的哈希（`certutil -hashfile <apk> SHA256`），方便别人确认拿到的是同一份。

发出去之后：**不要在赛季中途改靶子**。要升级就另开一季，并写清楚改了什么。
