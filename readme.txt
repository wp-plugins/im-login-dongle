=== Plugin Name ===
Contributors: ZeroCool51
Donate link: http://wpplugz.is-leet.com/
Tags: login dongle, login security, two step verification, two step login, im login, two step im login, instant messenger login, google talk login, extra security, pin login, code login, dongle, security
Requires at least: 3.0
Tested up to: 3.4.1
Stable tag: 0.11
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

A simple wordpress plugin that adds two way authentication via selected instant messenger.

== Description ==

This is a simple wordpress plugin that adds two step authentication to the login. The beauty of it is, that no mobile phones are required, and pretty much anyone has an IM accout nowadays.

How does it work?

*   You create an IM account (currently google talk is supported)
*   You add this account as the bot in the plugin settings page (this bot will be sending the login pin numbers to other users)
*   Users themselves disable or enable this feature

How does the login work when activated?

*   You login normally, if the credentials are correct,
*   a pin code is sent to your IM account,
*   you have 30 seconds to enter this pin code,
*   if the code is correct, you are logged in else you are logged out

What this plugin offers:

*   Two step authentication via IM accounts
*   Enable or disable the two step verification
*   Users themselves activate or disable this feature for them
*   Reset feature if IM servers are down
*   Customize PIN length
*   Add a custom message to the IM

== Installation ==

1. Upload the plugin directory to to the '/wp-content/plugins/' directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Create an instant messaging acount and add it in the plugin settings page
4. Enable the plugin in the plugin settings page
5. Go to your profile settings (Admin area->Users->Your profile), in the end edit the 'IM Dongle settings' section

== Frequently Asked Questions ==

None at the moment.

== Screenshots ==

1. Plugin settings page
2. User profile settings page (here each user can enable or disable the two step authentication themselves)
3. When plugin is activated, login procedure #1
4. When plugin is activated, login procedure #2
5. The disable screen for IM Login Dongle if IM servers are down

== Changelog ==

= 0.1 =
* The initial version of the plugin.

== Author ==

The author of this plugin is Bostjan Cigan, visit the [homepage](http://bostjan.gets-it.net "homepage").

== Homepage ==

Visit the [homepage](http://wpplugz.is-leet.com "homepage of im login dongle") of the plugin.

== Future versions ==

In the future all or some of these features might be added:

* Facebook IM support
* Windows Live Messenger support
* AIM support
* Logs of logins
* Sending IM login notifications to your bot account
