# testking
​主要新增功能说明
​批量扫描模式
从 url.txt 读取目标列表（支持去重和空行过滤）
多线程并发检测（默认5线程，可通过 -t 参数调整）
bash
python htoa_batch.py -f url.txt -t 10
​智能结果输出
控制台实时彩色状态显示（成功/失败/错误）
自动生成CSV格式报告（保存至 reports 目录）
csv
URL,状态,Webshell路径,错误信息
"http://target1.com",vulnerable,"http://target1.com/OAapp/.../normalLoginPageForOther.jsp",
"http://target2.com",safe,,"未匹配到有效路径"
​灵活的运行模式
​单目标模式：快速验证单个URL
bash
python htoa_batch.py -u http://target.com
​批量模式：适合红队渗透测试场景
bash
python htoa_batch.py -f urls.txt -t 20 -o scan_reports
​增强的错误处理
网络超时自动重试（内置15秒超时）
智能路径匹配（支持多种服务器配置）
​使用建议
​输入文件格式​（url.txt示例）
text
http://123.123.123.123:8899
https://oa.example.com:8443
192.168.1.100:8080
​典型输出示例
https://viar.com/600x200/000000/FFFFFF/?text=Console+Output
​防御规避技巧
随机化User-Agent（可在代码中扩展 utils/random_ua.py）
动态边界符生成（已在 upload_webshell 函数预留接口）
