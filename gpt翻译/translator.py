import ctypes
import tkinter as tk
import pyperclip
import openai
import os
from openai import OpenAI

os.environ["HTTP_PROXY"] = "http://127.0.0.1:7891"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7891"

api_key = ''
with open('key', 'r') as file:
    api_key = file.readline().strip()

client = OpenAI(api_key=api_key)

prompt = 'please provide a fluent and accurate translation suitable for the Chinese context from English to Chinese of the academic text enclosed in.'

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack(fill=tk.BOTH, expand=True)
        self.create_widgets()

    def create_widgets(self):
        self.text = tk.Text(self, font=("微软雅黑", 18))
        self.text.pack(side="top", fill=tk.BOTH, expand=True)

        self.translate_button = tk.Button(self,width=200,height=100)
        self.translate_button["text"] = "翻译"
        self.translate_button["command"] = self.translate
        self.translate_button.pack(side="bottom")

    def append_clipboard(self):
        clipboard_content = pyperclip.paste()
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, clipboard_content)

    def translate(self):
        self.query = prompt + "The text is as follows:" + pyperclip.paste()
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, "    ")
        self.num = 0
        self.stream = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "Act as an academic expert with specialized knowledge in computer science."},
                {
                    "role": "user",
                    "content": self.query,
                }
            ],
            model="gpt-3.5-turbo",
            stream=True,
        )
        self.process_next_chunk()

    def process_next_chunk(self):
        try:
            chunk = next(self.stream)
            slice = chunk.choices[0].delta.content or ""
            if '。' in slice:
                self.num += 1
                if self.num == 2:
                    self.text.insert(tk.END, slice+'\n\n    ')
                    self.num = 0
                else:
                    self.text.insert(tk.END, slice)
            else:
                self.text.insert(tk.END, slice)
            self.after(1, self.process_next_chunk)  # Call this method again after 1 millisecond.
        except StopIteration:
            pass  # No more chunks in the stream.


#告诉操作系统使用程序自身的dpi适配
ctypes.windll.shcore.SetProcessDpiAwareness(1)
#获取屏幕的缩放因子
ScaleFactor=ctypes.windll.shcore.GetScaleFactorForDevice(0)
#设置tkinter的缩放因子
root = tk.Tk()
root.geometry("875x1000")
root.tk.call('tk', 'scaling', 1.5)
app = Application(master=root)
app.mainloop()
