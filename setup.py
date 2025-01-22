from setuptools import setup, find_packages

setup(
    name='timesync',
    version='0.1.0',
    description='TimeSync - a tool to obtain hash using MS-SNTP for user accounts',
    author='t.me/riocool',
    author_email='riocool33@gmail.com',
    packages=find_packages(),
    install_requires=[
        'ldap3',
    ],
    entry_points={
        'console_scripts': [
            'timesync=timesync.main:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
) 