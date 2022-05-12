import os
if __name__ == '__main__':
    from PyInstaller.__main__ import run
    opts = ['mmj.py', '-w', '-F', '-i', 'test.ico',  '--clean', '--hidden-import','PyQt5.sip']
    run(opts)