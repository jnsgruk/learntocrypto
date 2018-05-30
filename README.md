### Learn to Crypto Challenges


#### Installation

- Make sure Node v10 is installed
- Run `npm install` inside the project directory

#### Usage

- First generate a secret key for your bank to encrypt its logs with, and start the bank.

```
$ SECRET_KEY=$(node secret-key.js) 
$ node bank.js $SECRET_KEY
```

- Now you're ready to start your teller. Before you go any further, open another terninal and register for a user ID.

```
$ node teller.js register
{ 
  cmd: 'register',
  msg: 'Customer registered',
  customerId: 'SOME_ID',
  customerSecret: 'SOME SECRET',
  hash: 'SOME_HASH' 
}
```

- Make sure to copy those customerID and customerSecret values somewhere safe, perhaps store them in shell variables.

```
$ customerID='SOME_ID'
$ customerSecret='SOME_SECRET'
```

- Now you're ready to make some transactions, or check your balance!

```
$ node teller.js $customerID $customerSecret balance
$ node teller.js $customerID $customerSecret deposit 250
$ node teller.js $customerID $customerSecret withdraw 50
```

- Enjoy!