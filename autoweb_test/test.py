import unittest
import sys
path = [
'C:\\Users\\xiaorang\\PycharmProjects\\autoweb',
'C:\\pycharm\\helpers\\pycharm_display',
'C:\\Users\\xiaorang\\PycharmProjects\\autoweb\\venv',
'C:\\Users\\xiaorang\\PycharmProjects\\autoweb\\venv\\lib\\site-packages',
'C:\\Users\\xiaorang\\PycharmProjects\\autoweb\\venv\\lib\\site-packages\\setuptools-40.8.0-py3.7.egg',
'C:\\Users\\xiaorang\\PycharmProjects\\autoweb\\venv\\lib\\site-packages\\pip-19.0.3-py3.7.egg',
'C:\\pycharm\\helpers\\pycharm_matplotlib_backend'
 ]
sys.path.extend(path)
discover = unittest.defaultTestLoader.discover(test_dir, pattern='test_identity_tid.py')
runner=unittest.TextTestRunner()
runner.run(discover)
