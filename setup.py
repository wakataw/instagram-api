from setuptools import setup, find_packages

setup(
    name='instagram',
    version='0.1a',
    description='Unofficial Instagram API',
    url='https://github.com/wakataw/instagram-api',
    author='Agung Pratama',
    author_email='prrtmgng@gmail.com',
    classifiers=[
        'Development Status :: 5 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
        'Natural Language :: English',
        'Natural Language :: Indonesian',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.5',
        'License :: OSI Approved :: MIT License'
    ],
    python_requires='>=3.6',
    install_requires=[
        'requests',
        'pycryptodomex',
        'PyNaCl',
    ],
    project_urls={
        'Bug Reports': 'https://github.com/wakataw/instagram-api/issues',
        'Source': 'https://github.com/wakataw/instagram-api'
    },
    keywords='api, instagram, graphql',
    packages=find_packages(exclude=['tests', 'examples']),
    zip_safe=True,
    license='MIT'
)
