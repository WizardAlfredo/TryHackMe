# Web Osint

## Whois Registration

We can confirm current registration status with a whois lookup.

A 'whois' lookup is the most basic form of domain recon available.
There are multiple websites that will do it for you as well.

Personally, I recommend just going directly to [lookup.icann.org](https://lookup.icann.org).
This should tell you the current hosting company used and name servers.
Looking at the raw data option will show further details.

We're looking for any data we might be able to use as pivot points.
Maybe an email address? Or better yet, a physical address or phone number?

Technically these are required in order to register any domain,
but most domain registrars offer some kind of privacy protection for a trivial fee,
if not free.

Anyway, let's see what we can find out!

## Ghosts of Websites Past

That's where **Archive.org** and the **Internet Wayback Machine** come into play.

Do yourself a favor and install the **archive.org** browser extension that will
automatically pull up an option to search for a site on the Wayback Machine when
it fails to load in the web browser.

## Digging into DNS

[ViewDNS.info](https://viewdns.info/)
provides a convenient UI for looking up registration information on a target website.
Using this information,
it may be possible to draw certain conclusions that are not clearly spelled out,
such as whether the website is hosted on a shared or dedicated IP address.
The answer to this question can imply things about the website's budget as
well as traffic.

## Taking a Peek Under The Hood Of A Website

Isn't it kind of interesting how the website disappeared for a period of time
and came back?

Clearly the purpose of the site is different now.
Let's roll up our sleeves and figure out what's going on.

First, do you have any gut feelings about this site? What is your overall impression?
Does it feel like a legitimate source of information?

Why?

You might consider some of the following points:

- Language - What grade level is the writing?
Does it seem to be written by a native English speaker?
- UX - Is it user friendly? Is the design modern?
- What pages does the site have?

I can tell you that this website conforms well to antiquated search engine
optimization (SEO) best practices.
You can read more about SEO best practices on ahrefs if you like before you continue.

Often, clues about a website and its creator/owner may be unintentionally left
behind in the source code of the website.
Pretty much every web browser will have a method of doing this.
It is well worth taking the time to become acquainted with how this works in
your browser of choice.
For Chrome on MacOS, you'll go to the top menu bar and choose
View > Developer > View Source.

Note: This also works on sites you visit within Archive.org's Wayback Machine.

Once the source code of the page loads, it's time to look around.
You don't have to understand HTML, CSS, or Javascript to read notes that the
developers left behind for themselves.
In HTML, comments begin with the characters

```html
<!--Don't forget to email Bob Loblaw when the site goes live at bob@fakeemail.com-->
```

As easy as that may be to read,
if it was buried inside a gigantic page full of code it could still be easy to miss.
That's where ctrl-F comes in. Here are some good things to search for with ctrl-f:

|Search Term|  Explanation| More information
|---|---|---
|`<!--`|Comments|See above
|@|email addresses|[Pivoting from an Email address](https://nixintel.info/osint/12-osint-resources-for-e-mail-addresses/)
|ca-pub|Google Publisher ID|[Google's Description](https://support.google.com/adsense/answer/105516?hl=en)
|ua-|Google AdSense ID|[Bellingcat Tutorial](https://www.bellingcat.com/resources/how-tos/2015/07/23/unveiling-hidden-connections-with-google-analytics-ids/)
|.jpg|Also try other image file extensions|Likely to reveal more directory structure

```json
```
