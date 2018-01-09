# Niirrty.Security.Password

A little password-security library.

It defines only a single class `Niirrty\Security\Password\PasswordSecurityCheck` that can be used to check the
quality of a password.

## Installation

Its a composer package, so you can install it by composer

```bash
composer require niirrty/niirrty.security.password ~0.1
```

or inside the composer.json

```json
{
   "require": {
      "php": ">=7.1",
      "composer require niirrty/niirrty.security.password": "~0.1"
   }
}
```

## How it works?

It generates 4 different password quality indicators:

1. **Password Length**: Max quality can be reached by using 11 or more characters 
2. **Character diversity**: The quality in relation to how many different chars are used
3. **Character type diversity**: The quality in relation to how many different char types are used (letters-lower,
   letters-upper, numbers, other)
4. **Known by Top lists**: 1 if known by Top 10 password lists, 2 if known by Top 25 password lists and 5 if known by
   Top 50 password lists, otherwise 10
   
The check, if a password is inside a password list Top 10/25/50 uses a SQLite DB in Background. The DB defines all
unique Top10, Top25 and Top50 passwords, extracted from [SecLists](https://github.com/danielmiessler/SecLists)
password files, excluding spanish and not *.txt files. 

Each uses a value between 0 (no security) and 10 (max security)

The lowest value of the 4 indicators will be returned by ->getQuality()

The password self is not stored inside a class instance.


## Usage

This is a simple usage example:

```php
# include __DIR__ . '/vendor/autoload.php';

use \Niirrty\Security\Password\PasswordSecurityCheck;

$passwords = [
   '',
   '0',
   '1',
   '22',
   'aaa',
   'aaaa',
   'AAAAA',
   '123456',
   '_______',
   'gEhe1m',
   '$4QT5/_8',
   '123456789'
];

foreach ( $passwords as $password )
{
   echo $password, ': ', ( new PasswordSecurityCheck( $password ) )->getQuality(), "\n";
}
```

will output:

```
: 0                              <== LenQ=0  DivQ=0  DivTQ=0  TopQ=1
0: 0                             <== LenQ=0  DivQ=1  DivTQ=2  TopQ=1
1: 0                             <== LenQ=0  DivQ=1  DivTQ=2  TopQ=1
22: 1                            <== LenQ=1  DivQ=1  DivTQ=2  TopQ=10
aaa: 1                           <== LenQ=2  DivQ=1  DivTQ=2  TopQ=10
aaaa: 1                          <== LenQ=3  DivQ=1  DivTQ=2  TopQ=1
AAAAA: 1                         <== LenQ=4  DivQ=1  DivTQ=2  TopQ=10
123456: 1                        <== LenQ=5  DivQ=8  DivTQ=2  TopQ=1
_______: 1                       <== LenQ=6  DivQ=1  DivTQ=2  TopQ=10
gEhe1m: 5                        <== LenQ=5  DivQ=6  DivTQ=6  TopQ=10
$4QT5/_8: 7                      <== LenQ=7  DivQ=8  DivTQ=8  TopQ=10
123456789: 1                     <== LenQ=8  DivQ=10 DivTQ=2  TopQ=1
```

Used abbr. above are:

* **LenQ** : Password length quality
* **DivQ** : Character diversity quality
* **DivTQ**: Character type diversity quality
* **TopQ** : Known by Top lists quality

