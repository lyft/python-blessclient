import platform
import os
from Tkinter import Tk, Label, Entry, Button, ACTIVE, W, mainloop


class TokenInputGUI(object):
    def show_entry_fields(self, event=None):
        self.code = self.e1.get()
        self.master.withdraw()
        self.master.quit()

    def quit(self):
        self.master.quit()
        self.code = None

    def doGUI(self, hostname=None):
        self.master = Tk()
        self.master.title('Blessclient - MFA')
        textmsg = 'Enter your AWS MFA code: '
        if hostname:
            textmsg = 'Enter your AWS MFA code to connect to {}: '.format(hostname)
        Label(self.master, text=textmsg).grid(row=0)
        self.e1 = Entry(self.master)
        self.e1.grid(row=0, column=1, padx=4)
        Button(self.master, text='OK', command=self.show_entry_fields, default=ACTIVE).grid(row=3, column=0, sticky=W, pady=4)
        Button(self.master, text='Cancel', command=self.quit).grid(row=3, column=1, sticky=W, pady=4)

        self.center()
        self.master.bind('<Return>', self.show_entry_fields)
        self.master.lift()
        self.master.attributes('-topmost', True)
        self.master.focus_force()
        self.e1.focus_set()
        if platform.system() == 'Darwin':
            try:
                from Cocoa import (
                    NSRunningApplication,
                    NSApplicationActivateIgnoringOtherApps
                )

                app = NSRunningApplication.runningApplicationWithProcessIdentifier_(
                    os.getpid()
                )
                app.activateWithOptions_(NSApplicationActivateIgnoringOtherApps)
            except ImportError:
                pass

        mainloop()

    # http://stackoverflow.com/questions/3352918/how-to-center-a-window-on-the-screen-in-tkinter
    def center(self):
        self.master.update_idletasks()
        w = self.master.winfo_screenwidth()
        h = self.master.winfo_screenheight()
        size = tuple(int(_) for _ in self.master.geometry().split('+')[0].split('x'))
        x = w / 2 - size[0] / 2
        y = h / 2 - size[1] / 2
        self.master.geometry("%dx%d+%d+%d" % (size + (x, y)))
