
  
<h1  align="center">Security Thing for your Project 🛡️</h1>

  

<p>

  

<img  alt="Version"  src="https://img.shields.io/badge/version-1.0.2-blue.svg?cacheSeconds=2592000"  />

  

<a  href="#"  target="_blank">

  

<img  alt="License: MIT"  src="https://img.shields.io/badge/License-MIT-yellow.svg"  />

  

</a>

  

</p>

  

  

> Validate your data in server or client for security

  

> Supports CommonJS and ES6

  

  

##  Install

  

  

```sh
npm install validate-things
```

  

  

##  Functions Usage

### Import Functions:
```js
import { function } from 'validate-things'; // ES6
const { function } = require('validate-things') // CommonJS
```

###  Validate Email:
```js
ValidateEmail({ email });
// email: string
```

###  Validate String for Vulnerabilities and length:

```js
ValidateString({ string, minLength, maxLength, securityLevel, log });
// string: string
// minLength: number (minimum length you need)
// maxLength?: number (maximum length you need)
// securityLevel?: "high" | "normal" | "none" [default: "high"] (check for possible vulnerabilities in string)
// log?: boolean [default: false] (log checks in console)
```

###  Check for XSS (Cross-Site-Scripting) Attacks:

```js
isXSS({ string });
// string: string
```

###  Check for SQL Injection:

```js
isSQLInjection({ string });
// string: string
```

###  Check for XML External Entity (XXE) Injection:

```js
isXXEInjection({ string });
// string: string
```

###  Check for LDAP Injection:

```js
isLDAPInjection({ string });
// string: string
```

###  Check for Command Injection:

```js
isCommandInjection({ string });
// string: string
```

##  Author

👤 **Shubhankar Trivedi**

* Website: shubhankartrivedi.com

* Github: [@shubhankartrivedi](https://github.com/shubhankartrivedi)

  

  

##  Show your support

  

  

Give a ⭐️ if this project helped you!

  

  

***