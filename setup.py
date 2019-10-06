from distutils.core import setup

setup(
  name                  = 'metame',
  packages              = ['metame'],
  version               = '0.4',
  description           = 'metame is a metamorphic code engine for arbitrary executables',
  author                = 'Alberto Ortega',
  author_email          = 'aortega.lms+metame@gmail.com',
  url                   = 'https://github.com/a0rtega/metame',
  download_url          = 'https://github.com/a0rtega/metame/archive/master.tar.gz',
  scripts               = ['scripts/metame'],
  install_requires      = ["keystone-engine", "r2pipe"],
  keywords              = ['metamorphic', 'code', 'engine'],
  classifiers = [
                        'Topic :: Security',
                        'Environment :: Console',
                        'Operating System :: OS Independent',
                        'Intended Audience :: Developers'
                ],
)

