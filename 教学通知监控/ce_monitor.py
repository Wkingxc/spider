import requests
from lxml import etree
from datetime import datetime
import json
import time

headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36',
    'connection': 'close',
}

# 发送给微信机器人
def send_text(content, mentioned_list=None, mentioned_mobile_list=None):
    webhook = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=58fe4dca-7acf-42fb-9f5f-7375abacf614'
    header = {
        "Content-Type": "application/json",
        "Charset": "UTF-8"
    }
    data = {
        "msgtype": "text",
        "text": {
            "content": content, "mentioned_list": mentioned_list, "mentioned_mobile_list": mentioned_mobile_list
        }
    }
    data = json.dumps(data)
    info = requests.post(url=webhook, data=data, headers=header)


articles = []
# 监测网站今天是否有新的通知公告
def monitor():
    url = 'https://ce.xidian.edu.cn/sy/bkjy/jxtz.htm'
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        tree = etree.HTML(r.content)
        article = tree.xpath("//li[@id='line_u8_0']/a")[1]
        news_title = article.xpath("./p")[0].text
        news_date = article.xpath("./i")[0].text
        if news_date == datetime.now().strftime('%Y-%m-%d'):
            if news_title not in articles:
                articles.append(news_title)
                content = f'网信院本科教育：\n{news_title}'
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f'{current_time}-{content}')
                send_text(content)

def monitor2():
    url = 'https://ce.xidian.edu.cn/sy/tzgg.htm'
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        tree = etree.HTML(r.content)
        article = tree.xpath("//li[@id='line_u8_0']/a")[1]
        news_title = article.xpath("./p")[0].text
        news_date = article.xpath("./i")[0].text
        if news_date == datetime.now().strftime('%Y-%m-%d'):
            if news_title not in articles:
                articles.append(news_title)
                content = f'网信院通知公告：\n{news_title}'
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f'{current_time}-{content}')
                send_text(content)


while True:
    try:
        monitor()
        monitor2()
    except Exception as e:
        with open('error.log', 'a') as f:
            f.write(f"An error occurred: {e}\n")
        send_text('出现错误,请修复！')
    time.sleep(600)