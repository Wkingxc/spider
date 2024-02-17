import ctypes
import tkinter as tk
import pyperclip
import openai
import os
from openai import OpenAI

# os.environ["HTTP_PROXY"] = "http://127.0.0.1:7891"
# os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7891"

api_key = 'sk-UBMI3ZmKqOKMBvzwjf6FttLzVA16Gjg6u91DERl1Z5Prpj5e'
client = OpenAI(api_key=api_key,base_url="https://api.chatanywhere.tech/v1")

prompt = 'please provide a fluent and accurate translation suitable for the Chinese context from English to Chinese of the academic text enclosed in.'

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack(fill=tk.BOTH, expand=True)
        self.create_widgets()
        self.previous_clipboard = pyperclip.paste()[:10]  # Save the first 10 characters of the clipboard.
        self.check_clipboard()  # Start checking the clipboard.

    def create_widgets(self):
        self.text = tk.Text(self, font=("微软雅黑", 16))
        self.text.pack(side="top", fill=tk.BOTH, expand=True)

        # self.translate_button = tk.Button(self,width=200,height=100)
        # self.translate_button["text"] = "翻译"
        # self.translate_button["command"] = self.translate
        # self.translate_button.pack(side="bottom")

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
    
    def check_clipboard(self):
        current_clipboard = pyperclip.paste()[:10]  # Get the first 10 characters of the clipboard.
        if current_clipboard != self.previous_clipboard:  # If the clipboard has changed...
            self.previous_clipboard = current_clipboard  # Update the saved clipboard.
            self.translate()  # Trigger the translate function.
        self.after(500, self.check_clipboard)  # Check the clipboard again after 1 second.

#告诉操作系统使用程序自身的dpi适配
ctypes.windll.shcore.SetProcessDpiAwareness(1)
#获取屏幕的缩放因子
ScaleFactor=ctypes.windll.shcore.GetScaleFactorForDevice(0)
#设置tkinter的缩放因子
root = tk.Tk()
root.geometry("535x1077")
root.tk.call('tk', 'scaling', 1.5)
app = Application(master=root)
app.mainloop()
