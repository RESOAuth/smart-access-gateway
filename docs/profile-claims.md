# Names, pictures and what SAG is willing to say about somebody

SAG asserts one thing it can prove: an email address. Everything else on the
`profile` scope either came from an upstream provider or was guessed, and the two
should not look the same to a relying party.

## Relaying from an upstream

When a person signs in through Microsoft or Google, their `id_token` usually
carries a name and often a picture. Those are relayed to the relying party that
asked for the `profile` scope, filtered through a fixed allow list:

```ascii
name  given_name  family_name  middle_name  nickname
preferred_username  picture  locale  zoneinfo
```

Nothing else crosses. That is not tidiness: an upstream that could put arbitrary
claims into somebody else's `id_token` would be a way to attack the relying party
*through* SAG. In particular `sub` and `email` are never taken from an upstream -
SAG has already decided what those are - and a `picture` that is not an `https`
URL is dropped, because it is a value a relying party will put in an `<img>`.

Narrow it further if a deployment has no business carrying any of it:

```sh
PROFILE_CLAIMS=name given_name family_name
PROFILE_PICTURE=false
```

`PROFILE_PICTURE` is separate from the list because it is the one claim with a
side effect beyond SAG: a relying party rendering it makes every one of its
pages fetch an image from Google or Microsoft. It is also the only reason the
Content-Security-Policy on SAG's own screens allows `https:` images at all, so
switching it off narrows that too.

## The email code path, where there is nothing to relay

A person who signs in with an email code has given SAG one fact about
themselves. There is no name to relay, and a relying party that wants to greet
somebody has three options: print the raw address, ask for a name of its own, or
guess.

The honest position is that `name` is supposed to mean the person's name, and a
guess dressed as one is worse than no claim at all. So **inference is off by
default**. It is offered because the alternative deployments actually reach for
is worse: `jamie.taylor@example.org` printed into a greeting, or every relying
party building its own profile form.

```sh
PROFILE_NAME_FROM_EMAIL=infer
```

With that set, the local part is read the way people actually write addresses:

| Address | Guess |
| --- | --- |
| `jamie.taylor@` | Jamie Taylor |
| `jamie_taylor@`, `jamie-taylor@` | Jamie Taylor |
| `j.taylor@` | J. Taylor |
| `jamie.taylor+shopping@` | Jamie Taylor |
| `jamie@` | Jamie |

And it errs firmly towards saying nothing. A wrong guess is worse than no guess,
so all of these produce no `name` at all:

- anything with a digit in it - `jamie2` might be a second Jamie or a birth
  year, and there is no way to tell;
- a machine identifier: a long hexadecimal string, a UUID, a bare number;
- a role address - `admin`, `support`, `no-reply`, `postmaster` and the rest -
  which names a function rather than a person;
- a single letter, or more than four words, or anything that is not letters.

A separator is all it has to go on. Addresses are folded to lower case before
any of this happens - which is what stops one person holding two accounts - so
there is no case boundary left to split on and `jamietaylor@` becomes
"Jamietaylor", one word.

It will get other things wrong too. `van.der.berg` becomes "Van Der Berg", and
`mcdonald` becomes "Mcdonald". Which is why:

## A guess is labelled as one

Whenever `name` came from the address rather than from an upstream, the token
carries an extra claim:

```json
{
  "name": "Jamie Taylor",
  "urn:sag:name_inferred": true
}
```

There is no standard claim that means "this is our best guess", so this is a
namespaced one. A relying party that ignores it gets a sensible default; one that
reads it can treat the value as something to confirm on first sign-in rather than
as a fact, which is what it is. It appears in `claims_supported` in the discovery
document only when inference is switched on, like everything else there.

## Avatars, and why not Gravatar

```sh
PROFILE_AVATAR_FALLBACK=initials
```

Somebody with no upstream picture gets a small SVG with their initials on it,
inline as a `data:` URI - about 450 bytes, deterministic, so the colour does not
change between sign-ins. It is only drawn once there is a name to draw from:
initials taken from an opaque local part would be noise.

The obvious alternative is Gravatar or one of its equivalents, and it is not
offered. Those need the address, usually as an MD5 or SHA-256 hash, which hands
a third party a record of every person who signs in anywhere on the deployment -
and a hashed address is not anonymous, because the space of real addresses is
small enough to enumerate. An identity provider is the last place that trade
makes sense. An SVG drawn locally tells nobody anything.

## On SAG's own screens

The "continue signing in" and "sign out?" screens show the name and picture SAG
holds, because a person confirming an account recognises a name and a face faster
than they parse an address. The address is always shown as well, since that is
the thing actually being asserted.

```sh
PROFILE_SHOW_ON_SCREEN=false
```

turns that off without affecting what relying parties receive - for a deployment
where a shared machine might show somebody's name to the next person at it.
