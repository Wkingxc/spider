from lxml import etree
import requests
import os
import time
from alive_progress import alive_bar

proxies = {
    'https': 'http://127.0.0.1:7890',
    'http': 'http://127.0.0.1:7890'
}
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.1.3538.102 Safari/537.36',
    'Connection': 'close'
}

# 漫画地址
url = 'https://manhwa18.net/manga/thorns-on-innocence'


# 下载图片
def download_img(url,filename):
    requests.adapters.DEFAULT_RETRIES = 10 # 增加重连次数
    s = requests.session()
    s.keep_alive = False # 关闭多余连接 
    s.max_connections = 100 # 设置连接池最大数量
    p = s.get(url,headers=headers,proxies=proxies)
    if p.status_code==200:
        with open(filename,'wb') as f:
            f.write(p.content)
    # time.sleep(0.1)
    # print(f'{filename} downloads success!')

# 下载某一章节的图片
def download_chapter_img(chapter_url,chapter_id):
    count = 1
    path = './chapter{}/'.format(chapter_id)
    if not os.path.exists(path):
        os.makedirs(path)
    imgs = get_imgs(chapter_url)
    with alive_bar(len(imgs),title='Downloading') as bar:
        for p_url in imgs:
            bar()  # 显示进度
            filename = f'{path}{count}.jpg'
            if not os.path.exists(filename):
                download_img(p_url, filename)
            # else:
            #     print(f'{count}-',end='')
            count += 1

    print(f'chapter{chapter_id} downloads success!')

# 获取某一漫画的章节地址
def get_chapters(url):
    r = requests.get(url, proxies=proxies, headers=headers)
    if r.status_code==200:
        # with open('./chapters.html','wb') as f:
        #     f.write(r.content)
        # tree = etree.parse('chapters.html',etree.HTMLParser())
        tree = etree.HTML(r.content)
        xpath_pattern = "//ul[@class='list-chapters at-series']/a/@href"
        chapters = tree.xpath(xpath_pattern)
        print(f'获取章节地址成功!章节数为:{len(chapters)}')
        return chapters
    else:
        print(f'get_chapters error! error_code:{r.status_code}')

# 获取某一章节的图片地址
def get_imgs(url):
    r = requests.get(url,proxies=proxies,headers=headers)
    if r.status_code==200:
        # tree = etree.parse('pictures.html',etree.HTMLParser())
        tree = etree.HTML(r.content)
        xpath_pattern = "//div[@id='chapter-content']/img/@data-src"
        imgs = tree.xpath(xpath_pattern)
        print(f'获取图片地址成功!图片数为:{len(imgs)}')
        return imgs
    else:
        print(f'get_imgs error! error_code:{r.status_code}')   


def run(url):
    chapters = get_chapters(url)
    # while True:
    #     chapter = input('请输入要下载的章节:')
    #     chapter_url = chapters[-int(chapter)]
    #     download_chapter_img(chapter_url,chapter)
    for i in range(50,len(chapters)+1):
        print(f'正在下载第{i}章...')
        chapter_url = chapters[-i]
        print(chapter_url)
        download_chapter_img(chapter_url,i)


run(url)



