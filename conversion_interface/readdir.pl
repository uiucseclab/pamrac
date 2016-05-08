#!/usr/bin/perl

#Copyright 2015 Fred Douglas


use strict;
use warnings;
use Cwd;

#List all files in the directory tree rooted at $ARGV[0]. Output is returned
#on stdout, one file path per line.

die "Pass a directory path as an argument!" unless defined($ARGV[0]);

my $output_string = &recursiveDirList($ARGV[0], "");
print "$output_string\n";

sub recursiveDirList
{
	my ($to_search, $list_so_far) = @_;
	my ($start_dir) = &cwd;

	chdir($to_search) or die "Unable to enter dir $to_search:$!\n";
	opendir(SEARCHINGDIR, ".") or die "Unable to open $to_search:$!\n";
	my @names = readdir(SEARCHINGDIR) or die "Unable to read $to_search:$!\n";
	closedir(SEARCHINGDIR);

	foreach my $name (@names)
	{
		next if ($name eq "." or $name eq "..");
		
		$list_so_far = (-d "$to_search/$name")
					? ("$list_so_far" . "\n" . &recursiveDirList("$to_search/$name", $list_so_far)) 
					: ("$list_so_far" . "\n" . "$to_search/$name");
	}
	chdir($start_dir) or die "Unable to change back to dir $start_dir:$!\n";
	
	return $list_so_far;
}
