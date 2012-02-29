#!/usr/bin/perl

#pwsm is a password manager wich provides git-mergable datafiles and multiuser support. it uses gpg for encryption.

#Copyright (C) 2012 <Heinrich Schmidt>

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

use Clipboard;
#my $pw = Clipboard->paste; #get the clipboard entry
#Clipboard->copy($pw); #fill the clipboard


my $pwfile = ".pwfile"; #the default name of the password file, which could be in the current working directory 
$pwfile = "~/.pwfile" unless( -e $pwfile ) ; 
my $keyname = "testkey";
my $toClipboard = 1; #dont print the password, just copy it to the clipboard
my $addPw = 0;
my $changePw = 0;
my $deletePw = 0;#last feature which is needed, and only with 3 confirmations
my @keys; #i should add my own key here, so I can read all you passwords ;)
my $configFileName = "$ENV{HOME}/.pwsmrc";
my $isDefineUser = 0;


for(my $count = 0; $count < scalar @ARGV; $count ++)
{
	if($ARGV[$count] eq "--config-file")
	{
		$configFileName = $ARGV[$count];
	}
}


if(-e $configFileName) {
	open(fh, "<", $configFileName);
	@rc = <fh>;
	close(fh);
	foreach(@rc)
	{
		if(m/^default-key =/i)
		{
			s/^default-key = //;
			chomp();
			push @keys, $_;
#$keys[0] = $_;
		}
	}
}
else {
	print "configfile $configFileName does not exist, create? [N/y]";
	$answer = <STDIN>;
	if($answer=~m/y/i)
	{
		print "please announce your default public key: ";
		$answer = <STDIN>;
		open(fh, ">", $configFileName);
		print fh "default-key = $answer";
		close(fh);
		chomp($answer);
		$keys[0] = $answer;
	}
}



for(my $count = 0; $count < scalar @ARGV; $count++)
{
	if($ARGV[$count] eq "-f") {
		$pwfile = $ARGV[++$count];
	}
	elsif($ARGV[$count] eq "-k") {
		$keyname = $ARGV[++$count];
	}
	elsif($ARGV[$count] eq "-p") {
		$toClipboard = 0;
	}
	elsif($ARGV[$count] eq "-a") {
		$addPw = 1;
	}
	elsif($ARGV[$count] eq "-c") {
		$changePw = 1;
	}
	elsif($ARGV[$count] eq "-d") {
		$deletePw = 1;
	}
	elsif($ARGV[$count] eq "--def-user") {
		$isDefineUser = 1;
	}
	elsif($ARGV[$count] eq "-h") {
		print "USAGE:
--config-file file 
           defines the configfile which should be used, default is ~/.pwsmrc
-f file    defines the password file
-k name    descriptor of the password
-p         print password to stdout, and not to the clipboard
-a         add a new password
-c         change password
-d         delete password [not yet implemented]
-h         This message
--def-user
           prompts for the gpg key-ids which you want to use to encrypt for
";
		exit(0);
	}
}


unless(-e $pwfile)
{
	`echo "pwsm password file. Version 0.0.1\nPWLIST:" >> $pwfile`;
	print "aha\n";
}

if($isDefineUser == 1) {
	$isDefineUser = 1;
	print "actual pwfile: $pwfile\n";
	print "please write the key IDs comma seperated, begin with your own:\n";
	my $input = <STDIN>;
	$input =~ s/,/\n/;
	my $sign = `echo "$input" | gpg --clearsign`;
	print "$sign";
	$sign =~s/\n/\$/g;
	open(fh, "<", $pwfile);
	my @file = <fh>;
	close(fh);
	for(my $kount = 0; $kount < scalar @file; $kount++)
	{
		$_ = $file[$kount];
		if(m/^signkey:$keys[0]/)
		{
			print "ok\n";
			$file[$kount]= "signkey:$keys[0]\$$sign\n";
			$kount = scalar @file;
		}
		elsif(m/PWLIST:/) {				
			print "ok\n";
			$file[$kount]= "signkey:$keys[0]\$$sign\nPWLIST:\n";
			$kount = scalar @file;
		}
	}
#writes the password file:
	open(fh, ">", $pwfile);
	print fh @file;
	close(fh);
	exit(0);
}

sub getNewPw{
	my $newPw = "pw";
	if( $toClipboard == 1) 	{
		$newPw = Clipboard->paste; #get the clipboard entry
	}
	else {
		print "Please give the new password: ";
		$newPw = <STDIN>;
		chomp($newPw);
	}
	my $gpgKeys = " -r " . join(" -r ",@keys);
	#print "$gpgKeys\n";
	$gpgKeys =~ s/-r $//;
	my $newValue = `echo "$newPw" | gpg $gpgKeys -e -a`;
	$newValue=~s/\n/\$/g;
	return "$newValue\n";
}



#reads the password file:
open(fh, "<", "$pwfile");
	@file = <fh>;
close(fh);



#my $keylist = 1;
my $isPwList = 0;
my $isKey = 1; #is 1 if the actual line should be a key and not the value
my $isSearchedKey = 0; #is 1, when the next value is the desired one

my $kount;
for($kount = 0; $kount < scalar @file; $kount++)
{
	$_ = $file[$kount];
	if(m/^PWLIST:$/) {
		$isPwList = 1;
	}
	elsif( $isPwList == 1 )	{
		if( $isKey == 1) {
			if(m/^$keyname$/) {
				$isSearchedKey = 1;
			}
		}
		else {
			if( $isSearchedKey == 1 )
			{
				$addPw = 0; #key already exists, adding is not possible

				if( $changePw == 1) {
					$file[$kount] = getNewPw();
				}
				else {

					s/\$/\n/g;
					my $pw = `echo "$_" | gpg -d`;
					chomp($pw);
					if( $toClipboard == 1 )	{
						Clipboard->copy($pw); #fill the clipboard
					}
					else {
						print "$pw\n";
					}
				}
				
			}
			$isSearchedKey = 0;
		}


		$isKey = ( $isKey + 1 ) % 2;
	}
	elsif(m/^signkey:/) {
		s/^signkey://;
		s/........\$//;
		my $keyid = $&;
		$keyid =~s/\$//;
		print "$keyid\n";
		if($keyid eq $keys[0]) #the first key in the configfile must be you own key
		{
			s/\$/\n/g;
			my $pw = `echo "$_" | gpg --verify --logger-fd 1 `;
			$pw=~ s/\".*\"//g;
			$pw=~ s/\n.*//;
			my $test = system("echo \"$_\" | gpg --verify");
			if($pw=~m/$keys[0]/)
			{
				@keys = qw ();
				print "ok\n";
				my $qount = 3;
				@sig = split/\n/;
				until($sig[$qount]=~m/-----BEGIN PGP SIGNATURE-----/)
				{
					print "$sig[$qount]\n";
					push @keys, $sig[$qount]; 
					$qount++;
				}
			}
			chomp($pw);
		}
	}
	else {
		#print "TODO\n";
	}
}

if( $addPw == 1) {
	print "add pw";
	$file[$kount] = "$keyname\n";
	$file[$kount+1] = getNewPw();
}

#writes the password file:
open(fh, ">", "$pwfile");
	print fh @file;
close(fh);
