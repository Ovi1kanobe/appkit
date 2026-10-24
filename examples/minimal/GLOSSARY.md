# AppKit example

The example's own terms: a shared list of notes, the status of the process, and the email provider's API key.
Each term is the name in the code, the requirements, and on the pages.

## Language

**Note**:
A short text of 1 to 500 characters that a member or a visitor writes for everyone who reads notes.
_Avoid_: Message, post, comment

**Author**:
The member or visitor who wrote a note; only a member who is the author deletes it.
_Avoid_: Owner, creator

**Member**:
A signed-in person in the members group, who reads and writes notes and watches the status.
_Avoid_: User

**Admin**:
A signed-in person in the admins group, who sets the API key.
_Avoid_: Administrator, superuser

**Visitor**:
Someone who is not signed in and reads or writes notes through the public routes; members see a visitor's note as Anonymous.
_Avoid_: Guest, anonymous user

**Profile**:
What the app knows about a signed-in person: their subject and email.
_Avoid_: Account, user record

**Status**:
How long the process has been running, which Diagnostics reports every five seconds.
_Avoid_: Health, metrics

**API key**:
The email provider's key, stored encrypted and shown only as set and its last four characters.
_Avoid_: Credential, secret

**Monitor**:
The app that reads the status with its own Rauthy client token.
_Avoid_: Consumer, caller
