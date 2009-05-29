#/*
# * Based on sftp-server.c
# * Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.
# *
# * Ported to Perl and extended by Simon Day
# * Copyright (c) 2009 Pirum Systems Ltd.  All rights reserved.
# *
# * Permission to use, copy, modify, and distribute this software for any
# * purpose with or without fee is hereby granted, provided that the above
# * copyright notice and this permission notice appear in all copies.
# *
# * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# */
#

package Net::SFTP::SftpServer;
require Exporter;
@ISA = qw(Exporter);

@EXPORT_OK = qw(
    ALL
    NET_SFTP_SYMLINKS
    NET_SFTP_RENAME_DIR
    SSH2_FXP_INIT
    SSH2_FXP_OPEN
    SSH2_FXP_CLOSE
    SSH2_FXP_READ
    SSH2_FXP_WRITE
    SSH2_FXP_LSTAT
    SSH2_FXP_STAT_VERSION_0
    SSH2_FXP_FSTAT
    SSH2_FXP_SETSTAT
    SSH2_FXP_FSETSTAT
    SSH2_FXP_OPENDIR
    SSH2_FXP_READDIR
    SSH2_FXP_REMOVE
    SSH2_FXP_MKDIR
    SSH2_FXP_RMDIR
    SSH2_FXP_REALPATH
    SSH2_FXP_STAT
    SSH2_FXP_RENAME
    SSH2_FXP_READLINK
    SSH2_FXP_SYMLINK
    logError
    logWarning
    logGeneral
    logDetail
);


%EXPORT_TAGS = (  ACTIONS => [ qw(
                              ALL
                              NET_SFTP_SYMLINKS
                              NET_SFTP_RENAME_DIR
                              SSH2_FXP_OPEN
                              SSH2_FXP_CLOSE
                              SSH2_FXP_READ
                              SSH2_FXP_WRITE
                              SSH2_FXP_LSTAT
                              SSH2_FXP_STAT_VERSION_0
                              SSH2_FXP_FSTAT
                              SSH2_FXP_SETSTAT
                              SSH2_FXP_FSETSTAT
                              SSH2_FXP_OPENDIR
                              SSH2_FXP_READDIR
                              SSH2_FXP_REMOVE
                              SSH2_FXP_MKDIR
                              SSH2_FXP_RMDIR
                              SSH2_FXP_STAT
                              SSH2_FXP_RENAME
                              SSH2_FXP_READLINK
                              SSH2_FXP_SYMLINK
                            ) ],
                  LOG  => [qw(
                              logError
                              logWarning
                              logGeneral
                              logDetail
                           )]);

use strict;
use warnings;

use version; our $VERSION = qv('1.0.4');

use Stat::lsMode;
use Fcntl qw( O_RDWR O_CREAT O_TRUNC O_EXCL O_RDONLY O_WRONLY SEEK_SET );
use POSIX qw(strftime);
use Sys::Syslog;

$SIG{__DIE__} = sub {  ## still dies upon return
		syslog 'warning', join(" : ", @_);
};

use Errno qw(:POSIX);

use constant TIMEOUT                        => 300;
use constant MAX_PACKET_SIZE                => 1024 * 1024;
use constant MAX_OPEN_HANDLES               => 512;

#/* version */
use constant SSH2_FILEXFER_VERSION          => 3;

#/* client to server */
use constant SSH2_FXP_INIT                  => 1;
use constant SSH2_FXP_OPEN                  => 3;
use constant SSH2_FXP_CLOSE                 => 4;
use constant SSH2_FXP_READ                  => 5;
use constant SSH2_FXP_WRITE                 => 6;
use constant SSH2_FXP_LSTAT                 => 7;
use constant SSH2_FXP_STAT_VERSION_0        => 7;
use constant SSH2_FXP_FSTAT                 => 8;
use constant SSH2_FXP_SETSTAT               => 9;
use constant SSH2_FXP_FSETSTAT              => 10;
use constant SSH2_FXP_OPENDIR               => 11;
use constant SSH2_FXP_READDIR               => 12;
use constant SSH2_FXP_REMOVE                => 13;
use constant SSH2_FXP_MKDIR                 => 14;
use constant SSH2_FXP_RMDIR                 => 15;
use constant SSH2_FXP_REALPATH              => 16;
use constant SSH2_FXP_STAT                  => 17;
use constant SSH2_FXP_RENAME                => 18;
use constant SSH2_FXP_READLINK              => 19;
use constant SSH2_FXP_SYMLINK               => 20;

# SFTP allow/deny actions

use constant ALL                            => 1000;
use constant NET_SFTP_RENAME_DIR            => 1001;
use constant NET_SFTP_SYMLINKS              => 1002;

#/* server to client */
use constant SSH2_FXP_VERSION               => 2;
use constant SSH2_FXP_STATUS                => 101;
use constant SSH2_FXP_HANDLE                => 102;
use constant SSH2_FXP_DATA                  => 103;
use constant SSH2_FXP_NAME                  => 104;
use constant SSH2_FXP_ATTRS                 => 105;

use constant SSH2_FXP_EXTENDED              => 200;
use constant SSH2_FXP_EXTENDED_REPLY        => 201;

#/* attributes */
use constant SSH2_FILEXFER_ATTR_SIZE        => 0x00000001;
use constant SSH2_FILEXFER_ATTR_UIDGID      => 0x00000002;
use constant SSH2_FILEXFER_ATTR_PERMISSIONS => 0x00000004;
use constant SSH2_FILEXFER_ATTR_ACMODTIME   => 0x00000008;
use constant SSH2_FILEXFER_ATTR_EXTENDED    => 0x80000000;

#/* portable open modes */
use constant SSH2_FXF_READ                  => 0x00000001;
use constant SSH2_FXF_WRITE                 => 0x00000002;
use constant SSH2_FXF_APPEND                => 0x00000004;
use constant SSH2_FXF_CREAT                 => 0x00000008;
use constant SSH2_FXF_TRUNC                 => 0x00000010;
use constant SSH2_FXF_EXCL                  => 0x00000020;

#/* status messages */
use constant SSH2_FX_OK                     => 0;
use constant SSH2_FX_EOF                    => 1;
use constant SSH2_FX_NO_SUCH_FILE           => 2;
use constant SSH2_FX_PERMISSION_DENIED      => 3;
use constant SSH2_FX_FAILURE                => 4;
use constant SSH2_FX_BAD_MESSAGE            => 5;
use constant SSH2_FX_NO_CONNECTION          => 6;
use constant SSH2_FX_CONNECTION_LOST        => 7;
use constant SSH2_FX_OP_UNSUPPORTED         => 8;
use constant SSH2_FX_MAX                    => 8;#8 is the highest that is available

use constant MESSAGE_HANDLER => {
    SSH2_FXP_INIT()        => 'processInit',
    SSH2_FXP_OPEN()        => 'processOpen',
    SSH2_FXP_CLOSE()       => 'processClose',
    SSH2_FXP_READ()        => 'processRead',
    SSH2_FXP_WRITE()       => 'processWrite',
    SSH2_FXP_LSTAT()       => 'processLstat',
    SSH2_FXP_FSTAT()       => 'processFstat',
    SSH2_FXP_SETSTAT()     => 'processSetstat',
    SSH2_FXP_FSETSTAT()    => 'processFsetstat',
    SSH2_FXP_OPENDIR()     => 'processOpendir',
    SSH2_FXP_READDIR()     => 'processReaddir',
    SSH2_FXP_REMOVE()      => 'processRemove',
    SSH2_FXP_MKDIR()       => 'processMkdir',
    SSH2_FXP_RMDIR()       => 'processRmdir',
    SSH2_FXP_REALPATH()    => 'processRealpath',
    SSH2_FXP_STAT()        => 'processStat',
    SSH2_FXP_RENAME()      => 'processRename',
    SSH2_FXP_READLINK()    => 'processReadlink',
    SSH2_FXP_SYMLINK()     => 'processSymlink',
    SSH2_FXP_EXTENDED()    => 'processExtended',
};

use constant MESSAGE_TYPES => {
    SSH2_FXP_INIT()        => 'SSH2_FXP_INIT',
    SSH2_FXP_OPEN()        => 'SSH2_FXP_OPEN',
    SSH2_FXP_CLOSE()       => 'SSH2_FXP_CLOSE',
    SSH2_FXP_READ()        => 'SSH2_FXP_READ',
    SSH2_FXP_WRITE()       => 'SSH2_FXP_WRITE',
    SSH2_FXP_LSTAT()       => 'SSH2_FXP_LSTAT',
    SSH2_FXP_FSTAT()       => 'SSH2_FXP_FSTAT',
    SSH2_FXP_SETSTAT()     => 'SSH2_FXP_SETSTAT',
    SSH2_FXP_FSETSTAT()    => 'SSH2_FXP_FSETSTAT',
    SSH2_FXP_OPENDIR()     => 'SSH2_FXP_OPENDIR',
    SSH2_FXP_READDIR()     => 'SSH2_FXP_READDIR',
    SSH2_FXP_REMOVE()      => 'SSH2_FXP_REMOVE',
    SSH2_FXP_MKDIR()       => 'SSH2_FXP_MKDIR',
    SSH2_FXP_RMDIR()       => 'SSH2_FXP_RMDIR',
    SSH2_FXP_REALPATH()    => 'SSH2_FXP_REALPATH',
    SSH2_FXP_STAT()        => 'SSH2_FXP_STAT',
    SSH2_FXP_RENAME()      => 'SSH2_FXP_RENAME',
    SSH2_FXP_READLINK()    => 'SSH2_FXP_READLINK',
    SSH2_FXP_SYMLINK()     => 'SSH2_FXP_SYMLINK',
    SSH2_FXP_EXTENDED()    => 'SSH2_FXP_EXTENDED',
    ALL()                  => 'ALL',
    NET_SFTP_SYMLINKS()    => 'NET_SFTP_SYMLINKS',
    NET_SFTP_RENAME_DIR()  => 'NET_SFTP_RENAME_DIR',
};

use constant ACTIONS => [
                              ALL,
                              NET_SFTP_SYMLINKS,
                              NET_SFTP_RENAME_DIR,
                              SSH2_FXP_OPEN,
                              SSH2_FXP_CLOSE,
                              SSH2_FXP_READ,
                              SSH2_FXP_WRITE,
                              SSH2_FXP_LSTAT,
                              SSH2_FXP_STAT_VERSION_0,
                              SSH2_FXP_FSTAT,
                              SSH2_FXP_SETSTAT,
                              SSH2_FXP_FSETSTAT,
                              SSH2_FXP_OPENDIR,
                              SSH2_FXP_READDIR,
                              SSH2_FXP_REMOVE,
                              SSH2_FXP_MKDIR,
                              SSH2_FXP_RMDIR,
                              SSH2_FXP_STAT,
                              SSH2_FXP_RENAME,
                              SSH2_FXP_READLINK,
                              SSH2_FXP_SYMLINK,
                            ];

my $USER = getpwuid($>);
my $ESCALATE_DEBUG = 0;
# --------------------------------------------------------------------
# Do evilness with symbol tables to ge
sub import{
  my $self = shift;
  my $opt = {};
  if (ref $_[0] eq 'HASH'){
    $opt = shift;
  }
  $opt->{log} ||= 'daemon';
  initLog($opt->{log});

  __PACKAGE__->export_to_level(1, $self, @_ ); # Call Exporter.
}
#-------------------------------------------------------------------------------
sub logItem {
  my ($level, $prefix, @msg) = @_;
  syslog $level, "[$USER]: $prefix" . join(" : ", @msg);
}
#-------------------------------------------------------------------------------
sub logDetail {
  logItem( $ESCALATE_DEBUG ? 'info' : 'debug', '', @_);
}
#-------------------------------------------------------------------------------
sub logGeneral {
  logItem('info', '', @_);
}
#-------------------------------------------------------------------------------
sub logWarning {
  logItem('warning', 'WARNING: ', @_);
}
#-------------------------------------------------------------------------------
sub logError {
  logItem('err', 'ERROR: ', @_);
}
#-------------------------------------------------------------------------------
sub initLog {
  my $syslog = shift;
  openlog( 'sftp', 'pid', $syslog);
  my ($remote_ip, $remote_port, $local_ip, $local_port) = split(' ', $ENV{SSH_CONNECTION});
  logGeneral "Client connected from $remote_ip:$remote_port";
  logDetail "Client connected to   $local_ip:$local_port";
}
#-------------------------------------------------------------------------------
sub new {
  my $class = shift;
  my $self  = {};
  bless $self, $class;
  Stat::lsMode->novice(0); #disable warnings from this module

  my %arg = @_;
  if (defined $arg{debug}     ){ $ESCALATE_DEBUG     = $arg{debug}  };

  $self->{home} = $arg{home} || '/home';
  $self->{home} =~ s!/$!!; # strip trailing /
  if (defined $arg{file_perms}){ $self->{file_perms} = $arg{file_perms} };
  if (defined $arg{dir_perms} ){ $self->{dir_perms}  = $arg{dir_perms}  };

  $self->{home_dir} = "$self->{home}/$USER";
  unless ( -d $self->{home_dir} ){
    logWarning "No sftp folder $self->{home_dir} found for $USER";
    exit 1;
  }
  unless ( -o $self->{home_dir} ){
    logWarning "No $self->{home_dir} is not owned by $USER";
    exit 1;
  }

  if (defined $arg{on_file_sent}){
    $self->{on_file_sent} = $arg{on_file_sent};
  }
  if (defined $arg{on_file_received}){
    $self->{on_file_received} = $arg{on_file_received};
  }

  $self->{use_tmp_upload} = (defined $arg{use_tmp_upload} and $arg{use_tmp_upload}) ? 1 : 0;

  $self->{max_file_size}  = (defined $arg{max_file_size}) ? $arg{max_file_size} : 0;

  $self->{valid_filename_char}  = (defined $arg{valid_filename_char} and ref $arg{valid_filename_char} eq 'ARRAY') ? quotemeta join ('', @{$arg{valid_filename_char}}) : '';


  if ( (defined $arg{deny} and $arg{deny} == ALL) or
       (defined $arg{allow} and $arg{allow} != ALL and not defined $arg{deny})
       ){
    $self->{deny} = { map { $_ => 1 } @{ACTIONS()} };
  }

  $arg{deny}  = (not defined $arg{deny})     ?  []         :
                (ref $arg{deny} eq 'ARRAY')  ? $arg{deny}  : [ $arg{deny} ];
  $arg{allow} = (not defined $arg{allow})    ?  []         :
                (ref $arg{allow} eq 'ARRAY') ? $arg{allow} : [ $arg{allow} ];

  for my $deny (@{$arg{deny}}){
    $self->{deny}{$deny} = 1;
  }
  for my $allow (@{$arg{allow}}){
    $self->{deny}{$allow} = 0;
  }

  # These have not been implemented yet
  $self->{deny}{SSH2_FXP_SETSTAT()}  = 1;
  $self->{deny}{SSH2_FXP_FSETSTAT()} = 1;
  $self->{deny}{SSH2_FXP_SYMLINK()}  = 1;
  $self->{deny}{SSH2_FXP_READLINK()} = 1;

  $self->{no_symlinks} = $self->{deny}{NET_SFTP_SYMLINKS()};
  if ($self->{no_symlinks}){
    # if denying symlinks then must deny these
    $self->{deny}{SSH2_FXP_SYMLINK()}  = 1;
    $self->{deny}{SSH2_FXP_READLINK()} = 1;
  }

  $arg{fake_ok} = (not defined $arg{fake_ok})    ?  []         :
                (ref $arg{fake_ok} eq 'ARRAY') ? $arg{fake_ok} : [ $arg{fake_ok} ];
  $self->{fake_ok} = { map {$_ => 1} @{$arg{fake_ok}} };

  $self->{handles} = {};
  $self->{handle_count} = 0;
  $self->{open_handle_count} = 0;

  return $self;
}
#-------------------------------------------------------------------------------
sub run {
  my $self = shift;
  while (1) {
    #/* copy stdin to iqueue */
    # Read 4 byte length of message
    # read length = payload
    my $packet_length = unpack("N", $self->readData(4));
    if ($packet_length > MAX_PACKET_SIZE){
      logError "Packet length of $packet_length received - exiting";
      exit 1;
    }

    my $data;
    eval {
      local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
      alarm TIMEOUT;
      $data = $self->readData( $packet_length );
      alarm 0;
    };
    if ($@) {
      logError "Connection timed out trying to read $packet_length bytes";
      exit 1;
    }

    my $payload       = Net::SFTP::SftpServer::Buffer->new( data => $data );
    #/* process requests from client */
    # note - all send data will be called from the handler for this message type
    $self->process($payload);
  }
}
#-------------------------------------------------------------------------------
sub readData {
  my $self = shift;
  my $len = shift;
  my $data = '';
  #logDetail "Going to read $len bytes";
  while (length $data < $len){
    my $buf;
    my $read_len = sysread( STDIN, $buf, $len - length $data );
    if ($read_len == 0) {
      logGeneral("Client disconnected");
      $self->closeHandlesOnExit();
      exit 0;
    }
    elsif ($read_len < 0) {
      logWarning("read error");
      $self->closeHandlesOnExit();
      exit 1;
    }
    else {
      $data .= $buf;
    }
  }
  return $data;
}
#-------------------------------------------------------------------------------
sub closeHandlesOnExit {
  my $self = shift;
  for my $fd (values %{$self->{handles}}){
    $fd->close();
    logWarning "Handle for " . $fd->getFilename() . " still open on client exit";
  }
}
#-------------------------------------------------------------------------------
sub sendMessage {
  my $self = shift;
  my $msg = shift;
  #/* copy stdin to iqueue */
  # calc 4 byte length of message
  # put on front of message
  # send to STDOUT
  my $l = length $msg;
  #logDetail "Going to send $l bytes";
  my $len = pack('N', $l);
  my $write_len = syswrite( STDOUT, $len . $msg );
  if ($write_len < 0){
    logWarning "Write Error $!";
    $self->closeHandlesOnExit();
    exit 1;
  }
}
#-------------------------------------------------------------------------------
sub getHandle {
  my $self = shift;
  my $handle_no = shift;
  my $type = shift || '';

  if (defined $self->{handles}{$handle_no} and ($type eq '' or $type eq $self->{handles}{$handle_no}->getType())){
    return $self->{handles}{$handle_no};
  }
  return;
}
#-------------------------------------------------------------------------------
sub deleteHandle {
  my $self = shift;
  my $handle_no = shift;

  $self->{open_handle_count}--;
  delete $self->{handles}{$handle_no};
}
#-------------------------------------------------------------------------------
sub addHandle {
  my $self = shift;
  my $new_handle = shift;
  $self->{handle_count}++;
  $self->{open_handle_count}++;
  if ($self->{open_handle_count} > MAX_OPEN_HANDLES){
    logWarning "Exceeding max handle count";
    return;
  }
  $self->{handles}{$self->{handle_count}} = $new_handle;
  return $self->{handle_count};
}
#-------------------------------------------------------------------------------
sub process {
  my $self = shift;
  my $payload = shift;
  my $message_type = $payload->getChar();

  logDetail "Got message_type " . MESSAGE_TYPES->{$message_type};

  if (defined MESSAGE_HANDLER->{$message_type}){
    my $method = MESSAGE_HANDLER->{$message_type};
    $self->$method($payload);
  }
  else {
    logWarning("Unknown message $message_type");
  }
  logWarning "Data left in buffer" unless $payload->done(); # check buffer is empty or warn
}
#-------------------------------------------------------------------------------
sub processInit {
  my $self = shift;
  my $payload = shift;

  $self->{client_version} = $payload->getInt();
  logDetail sprintf("client version %d", $self->{client_version});

  my $msg = pack('CN', SSH2_FXP_VERSION, SSH2_FILEXFER_VERSION);
  $self->sendMessage( $msg );
}
#-------------------------------------------------------------------------------
sub processOpen {
  my $self = shift;
  my $payload = shift;

  my $status = SSH2_FX_FAILURE;

  my $id     = $payload->getInt();
  my $name   = $payload->getString();
  my $pflags = $payload->getInt();    #/* portable flags */
  my $attr   = $payload->getAttrib();

  my $flags  = $self->flagsFromPortable($pflags);
  my $perm = defined $self->{file_perms}                        ? $self->{file_perms}  :
             ($attr->{flags} & SSH2_FILEXFER_ATTR_PERMISSIONS)  ? $attr->{perm}        : 0666;

  logDetail sprintf("open id %u name %s flags %d mode 0%o", $id, $name, $pflags, $perm);

  return if $self->denyOperation(SSH2_FXP_OPEN, $id);

  my $filename = $self->makeSafeFileName($name);

  if ((not defined $filename) or ($self->{no_symlinks} and -l $self->{home_dir} . $filename)){
    $self->sendStatus( $id, SSH2_FX_NO_SUCH_FILE );
    return;
  }

  # is this an upload
  my $use_temp = ($self->{use_tmp_upload}  and
                  $pflags & SSH2_FXF_CREAT and
                  $pflags & SSH2_FXF_WRITE and
                  $pflags & SSH2_FXF_TRUNC)     ? 1 : 0;

  my $fd = Net::SFTP::SftpServer::File->new($self->{home_dir} . $filename, $flags, $perm, $use_temp);
  if (not defined $fd) {
    $status = $self->errnoToPortable($! + 0);
  } else {
    my $handle = $self->addHandle($fd);
    if (defined $handle){
      logDetail "Opened handle $handle for file $filename";
      my $msg = pack('CNN', SSH2_FXP_HANDLE, $id, length $handle) . $handle;
      $self->sendMessage( $msg );
      return;
    }
  }

  $self->sendStatus( $id, $status );
}
#-------------------------------------------------------------------------------
sub processClose {
  my $self = shift;
  my $payload = shift;

  my $id     = $payload->getInt();
  my $handle = $payload->getString();
  logDetail sprintf("close id %u handle %d", $id, $handle);

  my $ret = -1;
  my $status;
  my $fd = $self->getHandle($handle);
  if (defined $fd){
    $ret = $fd->close();
    $status = $ret ? SSH2_FX_OK : $self->errnoToPortable($fd->err()) ;
    if( $fd->getType() eq 'file'){
      #log file transmission stats
      logGeneral $fd->getStats();
      if (defined $self->{on_file_sent} and $fd->wasSent()){
        $self->{on_file_sent}($fd->getFilename);
      }
      elsif (defined $self->{on_file_received} and $fd->wasReceived()){
        $self->{on_file_received}($fd->getFilename);
      }
    }
    $self->deleteHandle($handle);
  }
  else {
    $status = SSH2_FX_NO_SUCH_FILE;
  }

  $self->sendStatus( $id, $status );
}
#-------------------------------------------------------------------------------
sub processRead {
  my $self = shift;
  my $payload = shift;

  my $status = SSH2_FX_FAILURE;

  my $id      = $payload->getInt();
  my $handle  = $payload->getString();
  my $off     = $payload->getInt64();
  my $len     = $payload->getInt();

  logDetail sprintf("read id %u handle %d off %llu len %d", $id, $handle,$off, $len);

  return if $self->denyOperation(SSH2_FXP_READ, $id);

  my $fd = $self->getHandle($handle, 'file');
  if (defined $fd) {
    if (sysseek($fd, $off, SEEK_SET) < 0) {
      my $errno = $!+0;
      logWarning "processRead: seek failed $!";
      $status = $self->errnoToPortable($errno);
    } else {
      my $buf;
      my $ret = sysread($fd, $buf, $len);
      if ($ret < 0) {
        $status = $self->errnoToPortable($!+0);
      }
      elsif ($ret == 0) {
        $status = SSH2_FX_EOF;
      } else {
        my $msg = pack('CNN', SSH2_FXP_DATA, $id, $ret)  . $buf;
        $self->sendMessage( $msg );
        $status = SSH2_FX_OK;
        $fd->readBytes( $ret ) if $fd->getReadBytes() eq $off; #Only log sequential reads
      }
    }
  }
  if ($status != SSH2_FX_OK){
    $self->sendStatus( $id, $status );
  }
}
#-------------------------------------------------------------------------------
sub processWrite {
  my $self = shift;
  my $payload = shift;

  my $status = SSH2_FX_FAILURE;

  my $id      = $payload->getInt();
  my $handle  = $payload->getString();
  my $off     = $payload->getInt64();
  my $data    = $payload->getString();

  logDetail sprintf("write id %u handle %d off %llu len %d", $id, $handle, $off, length $data);

  return if $self->denyOperation(SSH2_FXP_WRITE, $id);


  my $fd = $self->getHandle($handle, 'file');
  if (defined $fd) {
    if ($self->{max_file_size} and $off + length $data > $self->{max_file_size}){
      logError "Attempt to write greater than Max file size, offset: $off, data length:" .  length $data . " on file ". $fd->getFilename();
      $self->sendStatus( $id, SSH2_FX_PERMISSION_DENIED );
      return;
    }
    elsif ($self->{max_file_size} and $off + length $data > 0.75 * $self->{max_file_size}){
      logWarning "Attempt to write greater than 75% of Max file size, offset: $off, data length:" .  length $data . " on file ". $fd->getFilename();
    }
    if (sysseek($fd, $off, SEEK_SET) < 0) {
      my $errno = $!+0;
      logWarning "processRead: seek failed $!";
      $status = $self->errnoToPortable($errno);
    } else {
      #/* XXX ATOMICIO ? */
      my $len = length $data;
      my $ret = syswrite($fd, $data, $len);
      if ($ret < 0) {
        logWarning "process_write: write failed";
        $status = $self->errnoToPrtable($!+0);
      }
      elsif ($ret == $len) {
        $fd->wroteBytes( $ret ) if $fd->getWrittenBytes() eq $off; #Only log sequential writes;
        $status = SSH2_FX_OK;
      } else {
        logGeneral("nothing at all written");
      }
    }
  }
  $self->sendStatus( $id, $status );
}
#-------------------------------------------------------------------------------
sub processDoStat{
  my $self = shift;
  my $mode    = shift;
  my $payload = shift;

  my $status = SSH2_FX_FAILURE;

  my $id   = $payload->getInt();
  my $name = $payload->getString();

  my $filename = $self->makeSafeFileName($name);
  logDetail sprintf("%sstat id %u name %s", $mode ? "l" : "", $id, $name);

  return if $self->denyOperation(($mode ? SSH2_FXP_LSTAT : SSH2_FXP_STAT), $id);

  if ((not defined $filename) or ($self->{no_symlinks} and -l $self->{home_dir} . $filename)){
    $self->sendStatus( $id, SSH2_FX_NO_SUCH_FILE );
    return;
  }

  my @st = $mode ? lstat($self->{home_dir} . $filename) : stat($self->{home_dir} . $filename);
  if (scalar @st == 0) {
    $status = $self->errnoToPortable($!+0);
  }
  else {
    my $attr = $self->statToAttrib(@st);
    my $msg = pack('CN', SSH2_FXP_ATTRS, $id) . $self->encodeAttrib( $attr );
    $self->sendMessage( $msg );
    $status = SSH2_FX_OK;
  }
  if ($status != SSH2_FX_OK){
    $self->sendStatus( $id, $status );
  }
}
#-------------------------------------------------------------------------------
sub processStat {
  my $self = shift;
  my $payload = shift;
  $self->processDoStat(0, $payload);
}
#-------------------------------------------------------------------------------
sub processLstat {
  my $self = shift;
  my $payload = shift;
  $self->processDoStat(1, $payload);
}
#-------------------------------------------------------------------------------
sub processFstat {
  my $self = shift;
  my $payload = shift;

  my $status = SSH2_FX_FAILURE;

  my $id      = $payload->getInt();
  my $handle  = $payload->getString();

  logDetail sprintf("fstat id %u handle %d", $id, $handle);

  return if $self->denyOperation(SSH2_FXP_FSTAT, $id);

  my $fd = $self->getHandle($handle);
  if (defined $fd) {
    my @st = stat($fd);
    if (scalar @st == 0) {
      $status = $self->errnoToPortable($!+0);
    } else {
      my $attr = $self->statToAttrib(@st);
      my $msg = pack('CN', SSH2_FXP_ATTRS, $id) . $self->encodeAttrib( $attr );
      $status = SSH2_FX_OK;
    }
  }
  if ($status != SSH2_FX_OK){
    $self->sendStatus( $id, $status );
  }
}
#-------------------------------------------------------------------------------
sub processSetstat {
  my $self = shift;
  my $payload = shift;

  #We choose not to allow any setting of stats

  my $id   = $payload->getInt();
  my $name = $payload->getString();

  my $filename = $self->makeSafeFileName($name);
  my $attr = $payload->getAttrib();
  logDetail sprintf("setstat id %u name %s", $id, $name);

  if ((not defined $filename) or ($self->{no_symlinks} and -l $self->{home_dir} . $filename)){
    $self->sendStatus( $id, SSH2_FX_NO_SUCH_FILE );
    return;
  }

  return if $self->denyOperation(SSH2_FXP_SETSTAT, $id);

  logError "processSetstat not implemented";
}
#-------------------------------------------------------------------------------
sub processFsetstat {
  my $self = shift;
  my $payload = shift;

  #We choose not to allow any setting of stats

  my $id   = $payload->getInt();
  my $handle = $payload->getString();

  my $attr = $payload->getAttrib();
  logDetail sprintf("setstat id %u name %s", $id, $handle);

  return if $self->denyOperation(SSH2_FXP_FSETSTAT, $id);

  logError "processFsetstat not implemented";
}
#-------------------------------------------------------------------------------
sub processOpendir {
  my $self = shift;
  my $payload = shift;

  my $status = SSH2_FX_FAILURE;

  my $id   = $payload->getInt();
  my $name = $payload->getString();

  my $pathname = $self->makeSafeFileName($name);

  logDetail sprintf("opendir id %u path %s", $id, $name);

  return if $self->denyOperation(SSH2_FXP_OPENDIR, $id);

  if ((not defined $pathname) or ($self->{no_symlinks} and -l $self->{home_dir} . $pathname)){
    $self->sendStatus( $id, SSH2_FX_NO_SUCH_FILE );
    return;
  }

  my $dirp = Net::SFTP::SftpServer::Dir->new($self->{home_dir} . $pathname);
  if (!defined $dirp) {
    $status = $self->errnoToPortable($!+0);
  } else {
    my $handle = $self->addHandle($dirp);
    if (defined $handle){
      my $msg = pack('CNN', SSH2_FXP_HANDLE, $id, length $handle) . $handle;
      $self->sendMessage( $msg );
      return;
    }
  }
  $self->sendStatus( $id, $status );
}
#-------------------------------------------------------------------------------
sub processReaddir {
  my $self = shift;
  my $payload = shift;

  my $id      = $payload->getInt();
  my $handle  = $payload->getString();

  logDetail(sprintf("readdir id %u handle %d", $id, $handle));

  return if $self->denyOperation(SSH2_FXP_READDIR, $id);

  my $dirp = $self->getHandle($handle, 'dir');
  if (not defined $dirp) {
    $self->sendStatus( $id, SSH2_FX_FAILURE );
  }
  else {
    my $fullpath = $dirp->getPath();
    my $stats = [];
    my $count = 0;
    while (my $dp = readdir($dirp)) {
      my $pathname = $fullpath . $dp;
      next if ( $self->{no_symlinks} and -l $pathname ); # we only inform the user about files and directories
      my @st = lstat($pathname);
      next unless scalar @st;
      my $file = {};
      $file->{attrib} = $self->statToAttrib(@st);
      $file->{name} = $dp;
      $file->{long_name} = $self->lsFile($dp, \@st);
      $count++;
      push @{$stats}, $file;
      #/* send up to 100 entries in one message */
      #/* XXX check packet size instead */
      last if $count == 100;
    }

    if ($count > 0) {
      $self->sendNames($id, $stats);
    }
    else {
      $self->sendStatus( $id, SSH2_FX_EOF );
    }
  }
}
#-------------------------------------------------------------------------------
sub processRemove {
  my $self = shift;
  my $payload = shift;

  my $id      = $payload->getInt();
  my $name    = $payload->getString();
  my $filename = $self->makeSafeFileName($name);

  logDetail sprintf("remove id %u name %s", $id, $name);

  return if $self->denyOperation(SSH2_FXP_REMOVE, $id);

  if ((not defined $filename) or ($self->{no_symlinks} and -l $self->{home_dir} . $filename)){
    $self->sendStatus( $id, SSH2_FX_NO_SUCH_FILE );
    return;
  }

  my $ret = unlink($self->{home_dir} . $filename);
  my $status = $ret ? $self->errnoToPortable($!+0) : SSH2_FX_OK;
  if ( $status == SSH2_FX_OK ){
    logGeneral "Removed $self->{home_dir}$filename";
  }
  $self->sendStatus($id, $status);
}
#-------------------------------------------------------------------------------
sub processMkdir {
  my $self = shift;
  my $payload = shift;

  my $id       = $payload->getInt();
  my $name     = $payload->getString();
  my $filename = $self->makeSafeFileName($name);
  my $attr     = $payload->getAttrib();

  my $mode = defined $self->{dir_perms}                         ? $self->{dir_perms}   :
             ($attr->{flags} & SSH2_FILEXFER_ATTR_PERMISSIONS)  ? $attr->{perm} & 0777 : 0777;

  logDetail sprintf("mkdir id %u name %s mode 0%o", $id, $name, $mode);

  return if $self->denyOperation(SSH2_FXP_MKDIR, $id);

  if (not defined $filename){
    $self->sendStatus( $id, SSH2_FX_NO_SUCH_FILE );
    return;
  }

  my $ret = mkdir($self->{home_dir} . $filename, $mode);
  my $status = $ret ? $self->errnoToPortable($!+0) : SSH2_FX_OK;
  $self->sendStatus($id, $status);
}
#-------------------------------------------------------------------------------
sub processRmdir {
  my $self = shift;
  my $payload = shift;

  my $id       = $payload->getInt();
  my $name     = $payload->getString();
  my $filename = $self->makeSafeFileName($name);

  logDetail sprintf("rmdir id %u name %s", $id, $name);

  return if $self->denyOperation(SSH2_FXP_RMDIR, $id);

  if (not defined $filename){
    $self->sendStatus( $id, SSH2_FX_NO_SUCH_FILE );
    return;
  }

  my $ret = rmdir($self->{home_dir} . $filename);
  my $status = $ret ? $self->errnoToPortable($!+0) : SSH2_FX_OK;
  $self->sendStatus($id, $status);
}
#-------------------------------------------------------------------------------
sub processRealpath {
  my $self = shift;
  my $payload = shift;

  my $id       = $payload->getInt();
  my $name     = $payload->getString();
  my $path     = $self->makeSafeFileName($name);

  logDetail sprintf("realpath id %u path %s", $id, $name);

  my $file = { name => $path, long_name => $path, attrib => { flags => 0 } };
  $self->sendNames($id, [ $file ]);
}
#-------------------------------------------------------------------------------
sub processRename {
  my $self = shift;
  my $payload = shift;

  my $id       = $payload->getInt();
  my $oname    = $payload->getString();
  my $oldpath  = $self->makeSafeFileName($oname);
  my $nname    = $payload->getString();
  my $newpath  = $self->makeSafeFileName($nname);

  logDetail sprintf("rename id %u old %s new %s", $id, $oname, $nname);

  return if $self->denyOperation(SSH2_FXP_RENAME, $id);

  if ((not defined $oldpath or not defined $newpath) or ($self->{no_symlinks} and -l $self->{home_dir} . $oldpath)){
    $self->sendStatus( $id, SSH2_FX_NO_SUCH_FILE );
    return;
  }

  return if -d $self->{home_dir} . $oldpath and $self->denyOperation(NET_SFTP_RENAME_DIR, $id);

  my $status = SSH2_FX_FAILURE;

  if (-f $self->{home_dir} . $oldpath) {
    #/* Race-free rename of regular files */
    if (! link($self->{home_dir} . $oldpath, $self->{home_dir} . $newpath)) {#FIXME test all codepaths
      # link method failed - try just a rename
      if (! rename($self->{home_dir} . $oldpath,$self->{home_dir} . $newpath)){
        $status = $self->errnoToPortable($!+0);
      }
      else {
        $status = SSH2_FX_OK;
      }
    }
    elsif (! unlink($self->{home_dir} . $oldpath)) {
      $status = $self->errnoToPortable($!+0);
      #/* clean spare link */
      unlink($self->{home_dir} . $newpath);
    }
    else {
      $status = SSH2_FX_OK;
    }
  }
  elsif ( -d $self->{home_dir} . $oldpath ) {
    if (! rename($self->{home_dir} . $oldpath,$self->{home_dir} . $newpath)){
      $status = $self->errnoToPortable($!+0);
    }
    else {
      $status = SSH2_FX_OK;
    }
  }
  else {
    # File does not exist or is a symlink - deny all knowlege
    $status = SSH2_FX_NO_SUCH_FILE;
  }
  if ( $status == SSH2_FX_OK ){
    logGeneral "Renamed $self->{home_dir}$oldpath to $self->{home_dir}$newpath";
  }
  $self->sendStatus($id, $status);
}
#-------------------------------------------------------------------------------
sub processReadlink {
  my $self = shift;
  my $payload = shift;

  my $id       = $payload->getInt();
  my $name     = $payload->getString();

  $self->sendStatus($id, SSH2_FX_NO_SUCH_FILE); # all symlinks hidden
}
#-------------------------------------------------------------------------------
sub processSymlink {
  my $self = shift;
  my $payload = shift;

  my $id       = $payload->getInt();
  my $oname    = $payload->getString();
  my $oldpath  = $self->makeSafeFileName($oname);
  my $nname    = $payload->getString();
  my $newpath  = $self->makeSafeFileName($nname);

  logDetail sprintf ("symlink id %u old %s new %s", $id, $oname, $nname);

  return if $self->denyOperation(SSH2_FXP_SYMLINK, $id);

  logError "processSymlink not implemented";
}
#-------------------------------------------------------------------------------
sub processExtended {
  my $self = shift;
  my $payload = shift;

  my $id       = $payload->getInt();
  my $request = $payload->getString();

  $self->sendStatus($id, SSH2_FX_OP_UNSUPPORTED);    #/* MUST */
}
#-------------------------------------------------------------------------------
sub sendNames {
  my $self = shift;
  my $id = shift;
  my $stats = shift;

  my $msg = pack('CNN', SSH2_FXP_NAME, $id, scalar @$stats );
  logDetail sprintf ("sent names id %u count %d", $id, scalar @$stats);
  for my $file (@$stats) {
    $msg .= pack('N', length $file->{name})      . $file->{name};
    $msg .= pack('N', length $file->{long_name}) . $file->{long_name};
    $msg .= $self->encodeAttrib($file->{attrib});
  }
  $self->sendMessage($msg);
}
#-------------------------------------------------------------------------------
sub denyOperation {
  my $self = shift;
  my ($op, $id) = @_;
  if (defined $self->{deny}{$op} and $self->{deny}{$op}){
    logWarning "Denying request operation: " . MESSAGE_TYPES->{$op} . ", id: $id";
    my $status = SSH2_FX_PERMISSION_DENIED;
    if (defined $self->{fake_ok}{$op} and $self->{fake_ok}{$op}){
      $status = SSH2_FX_OK;
    }
    $self->sendStatus($id, $status);
    return 1;
  }
  return;
}
#-------------------------------------------------------------------------------
sub lsFile {
  my $self = shift;
  my $name = shift;
  my $st = shift;
  my @ltime = localtime($st->[9]);
  my $mode = format_mode($st->[2]);

  my $user  = getpwuid($st->[4]);
  my $group = getgrgid($st->[5]);
  my $sz;
  if (scalar @ltime) {
    if (time() - $st->[9] < (365*24*60*60)/2){
      $sz = strftime "%b %e %H:%M", @ltime;
    }
    else {
      $sz = strftime "%b %e  %Y",   @ltime;
    }
  }

  my $ulen = length $user  > 8 ? length $user  : 8;
  my $glen = length $group > 8 ? length $group : 8;
  return sprintf("%s %3u %-*s %-*s %8llu %s %s", $mode, $st->[3], $ulen, $user, $glen, $group, $st->[7], $sz, $name);
}
#-------------------------------------------------------------------------------
sub sendStatus {
  my $self = shift;
  my ($id, $status) = @_;
  my @status_message = (
    "Success",                #/* SSH_FX_OK */
    "End of file",            #/* SSH_FX_EOF */
    "No such file",            #/* SSH_FX_NO_SUCH_FILE */
    "Permission denied",      #/* SSH_FX_PERMISSION_DENIED */
    "Failure",                #/* SSH_FX_FAILURE */
    "Bad message",            #/* SSH_FX_BAD_MESSAGE */
    "No connection",          #/* SSH_FX_NO_CONNECTION */
    "Connection lost",        #/* SSH_FX_CONNECTION_LOST */
    "Operation unsupported",  #/* SSH_FX_OP_UNSUPPORTED */
    "Unknown error"            #/* Others */
  );
  logDetail "Sending status: $status message: $status_message[$status] id: $id";
  my $msg = pack('CNN', SSH2_FXP_STATUS, $id, $status);
  if ($self->{client_version} >= 3){
    $msg .= pack('N', length $status_message[$status]) . $status_message[$status] . pack('N', 0);
  }
  $self->sendMessage( $msg );
}
#-------------------------------------------------------------------------------
sub makeSafeFileName {
  my $self = shift;
  # We force all file names to be treated as from / which we treat as the users home directory
  my $name = shift;

  $name = "/$name";
  while ($name =~ s!/\./!/!g)   {}
  $name =~ s!//+!/!g;

  my @path = split('/', $name);
  my @newpath;
  for my $d (@path){
    if ($d eq  '..'){
      pop @newpath;
    }
    elsif ($d ne '.') {
      if ($self->{valid_filename_char}){
        if ($d !~ /^[$self->{valid_filename_char}]*$/){
          logError "Invalid characters in $name";
          return;
        }
      }
      push @newpath, $d;
    }
    if ($self->{no_symlinks}){
      if ( -l $self->{home_dir} . join('/', @newpath) ){
        return; # no symlinks
      }
    }
  }

  $name = join('/', @newpath) || '/';
  $name =~ s!/.$!/!;
  return $name;
}
#-------------------------------------------------------------------------------
sub encodeAttrib {
  my $self = shift;
  my $attr = shift;
  $attr->{flags} ||= 0;
  my $msg = pack('N', $attr->{flags});
  if ($attr->{flags} & SSH2_FILEXFER_ATTR_SIZE){
    my $h = int($attr->{size} / (1 << 32));
    my $l =     $attr->{size} % (1 << 32);
    $msg .= pack('NN', $h, $l );
  }
  if ($attr->{flags} & SSH2_FILEXFER_ATTR_UIDGID) {
    $msg .= pack('N', $attr->{uid});
    $msg .= pack('N', $attr->{gid});
  }
  if ($attr->{flags} & SSH2_FILEXFER_ATTR_PERMISSIONS){
    $msg .= pack('N', $attr->{perm});
  }
  if ($attr->{flags} & SSH2_FILEXFER_ATTR_ACMODTIME) {
    $msg .= pack('N', $attr->{atime});
    $msg .= pack('N', $attr->{mtime});
  }
  return $msg;
}
#-------------------------------------------------------------------------------
sub statToAttrib {
  my $self = shift;
  my @stats = @_;
  #/* Convert from struct stat to filexfer attribs */
  my $attr = {};
  $attr->{flags} = 0;
  $attr->{flags} |= SSH2_FILEXFER_ATTR_SIZE;
  $attr->{size} = $stats[7];
  $attr->{flags} |= SSH2_FILEXFER_ATTR_UIDGID;
  $attr->{uid} = $stats[4];
  $attr->{gid} = $stats[5];
  $attr->{flags} |= SSH2_FILEXFER_ATTR_PERMISSIONS;
  $attr->{perm} = $stats[2];
  $attr->{flags} |= SSH2_FILEXFER_ATTR_ACMODTIME;
  $attr->{atime} = $stats[8];
  $attr->{mtime} = $stats[9];

  return $attr;
}
#-------------------------------------------------------------------------------
sub flagsFromPortable{
  my $self = shift;
  my $pflags = shift;
  my $flags = 0;

  if (($pflags & SSH2_FXF_READ) &&
      ($pflags & SSH2_FXF_WRITE)) {
    $flags = O_RDWR;
  }
  elsif ($pflags & SSH2_FXF_READ) {
    $flags = O_RDONLY;
  }
  elsif ($pflags & SSH2_FXF_WRITE) {
    $flags = O_WRONLY;
  }
  if ($pflags & SSH2_FXF_CREAT){
    $flags |= O_CREAT;
  }
  if ($pflags & SSH2_FXF_TRUNC){
    $flags |= O_TRUNC;
  }
  if ($pflags & SSH2_FXF_EXCL){
    $flags |= O_EXCL;
  }
  return $flags;
}
#-------------------------------------------------------------------------------
sub errnoToPortable {
  my $self = shift;
  my $errno = shift;

  if ($errno == 0){
    return SSH2_FX_OK;
  }
  elsif ( $errno ==  ENOENT or
          $errno ==  ENOTDIR or
          $errno ==  EBADF or
          $errno ==  ELOOP ){
    return SSH2_FX_NO_SUCH_FILE;
  }
  elsif ( $errno ==   EPERM or
          $errno ==   EACCES or
          $errno ==   EFAULT ){
    return SSH2_FX_PERMISSION_DENIED;
  }
  elsif ( $errno == ENAMETOOLONG or
          $errno ==   EINVAL){
    return SSH2_FX_BAD_MESSAGE;
  }
  else {
    return SSH2_FX_FAILURE;
  }
}
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
package Net::SFTP::SftpServer::Buffer;
use strict;
use warnings;

#/* attributes */
use constant SSH2_FILEXFER_ATTR_SIZE        => 0x00000001;
use constant SSH2_FILEXFER_ATTR_UIDGID      => 0x00000002;
use constant SSH2_FILEXFER_ATTR_PERMISSIONS => 0x00000004;
use constant SSH2_FILEXFER_ATTR_ACMODTIME   => 0x00000008;
use constant SSH2_FILEXFER_ATTR_EXTENDED    => 0x80000000;

1;
#-------------------------------------------------------------------------------
sub new {
  my $class = shift;
  my $self  = {};
  bless $self, $class;
  my %arg = @_;
  $self->{data} = $arg{data};
  return $self;
}
# ------------------------------------------------------------------------------
sub getInt {
  my $self = shift;
  my $i = substr($self->{data}, 0, 4);
  $self->{data} = substr($self->{data}, 4);
  return unpack("N", $i);
}
# ------------------------------------------------------------------------------
sub getInt64 {
  my $self = shift;
  my $i = substr($self->{data}, 0, 8);
  $self->{data} = substr($self->{data}, 8);
  my ($h, $l) = unpack("NN", $i);
  return ($h << 32) + $l;
}
# ------------------------------------------------------------------------------
sub getChar {
  my $self = shift;
  my $c = substr($self->{data}, 0, 1);
  $self->{data} = substr($self->{data}, 1);
  return unpack("C", $c);
}
# ------------------------------------------------------------------------------
sub getString {
  my $self = shift;
  my $len = $self->getInt();
  my $str = substr($self->{data}, 0, $len);
  $self->{data} = substr($self->{data}, $len);
  return $str;
}
#-------------------------------------------------------------------------------
sub getAttrib {
  my $self = shift;
  #/* Decode attributes in buffer */

  my $attr = {};

  $attr->{flags} = $self->getInt();
  if ($attr->{flags} & SSH2_FILEXFER_ATTR_SIZE){
    $attr->{size} = $self->getInt64();
  }
  if ($attr->{flags} & SSH2_FILEXFER_ATTR_UIDGID) {
    $attr->{uid} = $self->getInt();
    $attr->{gid} = $self->getInt();
  }
  if ($attr->{flags} & SSH2_FILEXFER_ATTR_PERMISSIONS){
    $attr->{perm} = $self->getInt();
  }
  if ($attr->{flags} & SSH2_FILEXFER_ATTR_ACMODTIME) {
    $attr->{atime} = $self->getInt();
    $attr->{mtime} = $self->getInt();
  }

  #/* vendor-specific extensions */
  if ($attr->{flags} & SSH2_FILEXFER_ATTR_EXTENDED) {
    my $count = $self->getInt();
    for (my $i = 0; $i < $count; $i++) {
      my $type = $self->getString();
      my $data = $self->getString();
      logDetail("Got file attribute \"%s\"", $type);
    }
  }
  return $attr;
}
# ------------------------------------------------------------------------------
sub done {
  my $self = shift;
  return 1 if length $self->{data} eq 0;
  return;
}
1;
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
package Net::SFTP::SftpServer::File;
use strict;
use warnings;

use base qw( IO::File );

my $TMP_EXT = ".SftpXFR.$$";

my %filename_of;
my %mode_of;
my %perm_of;
my %write_of;
my %read_of;
my %opentime_of;
my %use_temp_of;
my %err_of;
#-------------------------------------------------------------------------------
sub new {
  my $type = shift;
  my $class = ref($type) || $type || "Net::SFTP::SftpServer::File";
  my ($filename, $mode, $perm, $use_tmp) = @_;
  $use_tmp ||= 0;
  my $realfile = $filename;
  if ($use_tmp){
    $filename .= $TMP_EXT;
  }

  my $fd = $class->SUPER::new($filename, $mode, $perm);


  my $ident = scalar($fd);
  $filename_of{$ident} = $realfile;
  $mode_of{$ident}     = $mode;
  $perm_of{$ident}     = $perm;
  $write_of{$ident}    = 0;
  $read_of{$ident}     = 0;
  $opentime_of{$ident} = time();
  $use_temp_of{$ident} = $use_tmp;

  return $fd;
}
#-------------------------------------------------------------------------------
sub err {
  my $fd = shift;
  my $ident = scalar($fd);

  return $err_of{$ident};
}
#-------------------------------------------------------------------------------
sub close {
  my $fd = shift;
  my $ident = scalar($fd);

  my $ret = $fd->SUPER::close();
  unless ($ret){
    $err_of{$ident} = $!+0;
  }

  if ($use_temp_of{$ident}){
    rename $filename_of{$ident} . $TMP_EXT, $filename_of{$ident};
  }

  return $ret;
}
#-------------------------------------------------------------------------------
sub getFilename {
  my $fd = shift;
  my $ident = scalar($fd);
  return $filename_of{$ident};
}
#-------------------------------------------------------------------------------
sub getMode {
  my $fd = shift;
  my $ident = scalar($fd);
  return $mode_of{$ident};
}
#-------------------------------------------------------------------------------
sub getPerm {
  my $fd = shift;
  my $ident = scalar($fd);
  return $perm_of{$ident};
}
#-------------------------------------------------------------------------------
sub wroteBytes {
  my $fd = shift;
  my $ident = scalar($fd);
  my $size = shift;
  $write_of{$ident} += $size;
}
#-------------------------------------------------------------------------------
sub readBytes {
  my $fd = shift;
  my $ident = scalar($fd);
  my $size = shift;
  $read_of{$ident} += $size;
}
#-------------------------------------------------------------------------------
sub getWrittenBytes {
  my $fd = shift;
  my $ident = scalar($fd);
  return $write_of{$ident};
}
#-------------------------------------------------------------------------------
sub getReadBytes {
  my $fd = shift;
  my $ident = scalar($fd);
  $read_of{$ident};
}
#-------------------------------------------------------------------------------
sub getStats {
  my $fd = shift;
  my $ident = scalar($fd);
  my $stats = "Filename: $filename_of{$ident} ";
  my $dtime = (time() - $opentime_of{$ident}) || 1;
  if ($write_of{$ident} and $read_of{$ident}){
    ## reads and writes
    my $speed = int(($write_of{$ident} + $read_of{$ident}) / (1024 * $dtime));
    $stats .= "Received: $write_of{$ident} bytes Sent: $read_of{$ident} in $dtime seconds Speed: $speed K/s";
  }
  elsif ($write_of{$ident}){
    # File received
    my $speed = int($write_of{$ident} / (1024 * $dtime));
    $stats .= "Received: $write_of{$ident} bytes in $dtime seconds Speed: $speed K/s";
  }
  elsif ($read_of{$ident}){
    # File Sent
    my $speed = int($read_of{$ident} / (1024 * $dtime));
    $stats .= "Sent: $read_of{$ident} bytes in $dtime seconds Speed: $speed K/s";
  }
  return $stats;
}
#-------------------------------------------------------------------------------
sub wasReceived {
  my $fd = shift;
  my $ident = scalar($fd);
  if ($write_of{$ident} and ! $read_of{$ident} and -s $filename_of{$ident} eq $write_of{$ident}){
    return 1;
  }
  return;
}
#-------------------------------------------------------------------------------
sub wasSent {
  my $fd = shift;
  my $ident = scalar($fd);
  if ($read_of{$ident} and ! $write_of{$ident} and -s $filename_of{$ident} eq $read_of{$ident}){
    return 1;
  }
  return;
}
#-------------------------------------------------------------------------------
sub getType {
  my $fd = shift;
  return 'file';
}
1;
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
#-------------------------------------------------------------------------------
package Net::SFTP::SftpServer::Dir;
use strict;
use warnings;

use base qw( IO::Dir );

my %path_of;
my %dir_err_of;
#-------------------------------------------------------------------------------
sub new {
  my $type = shift;
  my $class = ref($type) || $type || "Net::SFTP::SftpServer::Dir";
  my $fd = $class->SUPER::new(@_);

  my ($path) = @_;
  $path .= '/';
  $path =~ s!//$!/!; # make sure we have a trailing /
  my $ident = scalar($fd);
  $path_of{$ident} = $path;

  return $fd;
}
#-------------------------------------------------------------------------------
sub err {
  my $fd = shift;
  my $ident = scalar($fd);

  return $dir_err_of{$ident};
}
#-------------------------------------------------------------------------------
sub close {
  my $fd = shift;
  my $ident = scalar($fd);

  my $ret = $fd->SUPER::close();
  unless ($ret){
    $dir_err_of{$ident} = $!+0;
  }

  return $ret;
}
#-------------------------------------------------------------------------------
sub getFilename {
  my $fd = shift;
  my $ident = scalar($fd);
  return "DIR$path_of{$ident}";
}
#-------------------------------------------------------------------------------
sub getPath {
  my $fd = shift;
  my $ident = scalar($fd);
  return $path_of{$ident};
}
#-------------------------------------------------------------------------------
sub getType {
  my $fd = shift;
  return 'dir';
}
1;
#-------------------------------------------------------------------------------
__END__
#-------------------------------------------------------------------------------
=head1 NAME

Net::SFTP::SftpServer - A Perl implementation of the SFTP subsystem with user access controls

=head1 SYNOPSIS

  use Net::SFTP::SftpServer;

  my $sftp = Net::SFTP::SftpServer->new();

  $sftp->run();

=head1 DESCRIPTION


A Perl port of sftp-server from openssh providing access control on a per user per command basis and improved logging via syslog

The limitations compared with the openssh implementation are as follows:

=over

=item *

Only files and directories are dealt with - other types are not returned on readdir

=item *

a virtual chroot is performed - / is treated as the users home directory from the
client perspective and all file access to / will be in /<home_path>/<username>
home_path is defined on object initialisation not accessed from /etc/passwd

=item *

all sym linked files or directories are hidden and not accessible on request

=item *

symlink returns permission denied

=item *

readlink returns file does not exist

=item *

setting of stats (set_stat or set_fstat) is disabled - client will receive permission denied

=item *

permissions for file or dir is defaulted - default set on object initialisation

=back

=head1 USAGE

Basic usage:

  use Net::SFTP::SftpServer;

Import options:

  :LOG    - Import logging functions for use in callbacks
  :ACTION - Import constants for Allow/Deny of actions

Configuring syslog:

Syslog output mode must be configured in the use statement of the module as follows:

  use Net::SFTP::SftpServer ( { log => 'local5' }, qw ( :LOG :ACTIONS ) );

Net::SFTP::SftpServer will default to using C<daemon> see your system's syslog documentation for more details


Options for object initialisation:

=over

=item

debug

Log debug level information. Deault=0 (note this will create very large log files - use with caution)

=item

home

Filesystem location of user home directories. default=/home

=item

file_perms

Octal file permissions to force on creation of files. Default=0666 or permissions specified by file open command from client

=item

dir_perms

Octal dir permissions to force on creation of directories. Default=0777 or permissions specified by mkdir command from client

=item

on_file_sent, on_file_received

References to callback functions to be called on complete file sent or received. Function will be passed the full path and filename on the filesystem as a single argument

=item

use_tmp_upload

Use temporary upload filenames while a file is being uploaded - this allows a monitoring script to know which files are in transit without having to watch file size.
Will be done transparantly to the user, the file will be renamed to the original file name when close. The temportary extension is ".SftpXFR.$$". Default=0

=item

max_file_size

Maximum file size (in bytes) which can be uploaded. Default=0 (no limit)

=item

valid_filename_char

Array of valid characters for filenames

=item

allow, deny

Actions allowed or denied - see L</PERMISSIONS> for details, Default is to allow ALL.

=item

fake_ok

Array of actions (see action contants in L</PERMISSIONS>) which will be given response SSH2_FX_OK instead of SSH2_FX_PERMISSION_DENIED when denied by above deny options. Default=[]

=back

=head1 PERMISSIONS

  ALL                      - All actions
  NET_SFTP_SYMLINKS        - Symlinks in paths to files (recommended deny to enforce chroot)
  NET_SFTP_RENAME_DIR      - Rename directories (recommended deny if also denying SSH2_FXP_MKDIR)
  SSH2_FXP_OPEN
  SSH2_FXP_CLOSE
  SSH2_FXP_READ
  SSH2_FXP_WRITE
  SSH2_FXP_LSTAT
  SSH2_FXP_STAT_VERSION_0
  SSH2_FXP_FSTAT
  SSH2_FXP_SETSTAT         - Automatically denied, not implemented in module
  SSH2_FXP_FSETSTAT        - Automatically denied, not implemented in module
  SSH2_FXP_OPENDIR
  SSH2_FXP_READDIR
  SSH2_FXP_REMOVE
  SSH2_FXP_MKDIR
  SSH2_FXP_RMDIR
  SSH2_FXP_STAT
  SSH2_FXP_RENAME
  SSH2_FXP_READLINK        - Automatically denied, not implemented in module
  SSH2_FXP_SYMLINK         - Automatically denied, not implemented in module

=head1 CALLBACKS

Callback functions can be used to perform actions when files are sent or received, for example move a fully downloaded file to a processed directory or move a received file into an input directory.

=head1 LOGGING

If :LOG is used when including Net::SFTP::SftpServer the following logging functions will be available:

  logError    - syslog with a log level of error
  logWarning  - syslog with a log level of warning
  logGeneral  - syslog with a log level of info
  logDetail   - syslog with a log level of debug, unless object was created with debug=>1 then syslog with a level of info

=head1 HARDENED EXAMPLE SCRIPT

The following example script shows how this module can be used to give far greater control over what is allowed on your SFTP server.

This setup is aimed at admins which want to user SFTP uploads but do not wish to grant users a system account.
You will also need to set both the SFTP subsystem and the user's shell to the sftp script, eg /usr/local/bin/sftp-server.pl

This configuration:

=over

=item * Enforces that users can only access the sftp script, not an ssh shell.

=item * Chroots them into their home directory in /var/upload/sftp

=item * Sets all file permissions to 0660 and does not permit users to change them.

=item * Does not allow symlinks, making directories or renaming directories, but allows all other normal actions.

=item * Has a max upload filesize of 200Mb

=item * Has a script memory limit of 100Mb for safety

=item * Will log actions by user sftptest in debug mode

=item * Will only allow alphanumeric plus _ . and - in filenames

=item * Will call ActionOnSent and ActionOnReceived respectively when files have been sent or received.

=back

  #!/usr/local/bin/perl

  use strict;
  use warnings;
  use Net::SFTP::SftpServer ( { log => 'local5' }, qw ( :LOG :ACTIONS ) );
  use BSD::Resource;        # for setrlimit

  use constant DEBUG_USER => {
    SFTPTEST => 1,
  };


  # Security - make sure we have started this as sftp not ssh
  unless ( scalar @ARGV == 2 and
           $ARGV[0] eq '-c'  and
           ($ARGV[1] eq '/usr/local/bin/sftp-server.pl') ){

         logError "SFTP connection attempted for application $ARGV[0] - exiting";
         print "\n\rYou do not have permission to login interactively to this host.\n\r\n\rPlease contact the system administrator if you believe this to be a configuration error.\n\r";
         exit 1;
  }

  my $MEMLIMIT = 100 * 1024 * 1024; # 100 Mb

  # hard limits on process memory usage;
  setrlimit( RLIMIT_RSS,  $MEMLIMIT, $MEMLIMIT );
  setrlimit( RLIMIT_VMEM, $MEMLIMIT, $MEMLIMIT );

  my $debug = (defined DEBUG_USER->{uc(getpwuid($>))} and DEBUG_USER->{uc(getpwuid($>))}) ? 1 : 0;

  my $sftp = Net::SFTP::SftpServer->new(
    debug               => $debug,
    home                => '/var/upload/sftp',
    file_perms          => 0660,
    on_file_sent        => \&ActionOnSent,
    on_file_received    => \&ActionOnReceived,
    use_tmp_upload      => 1,
    max_file_size       => 200 * 1024 * 1024,
    valid_filename_char => [ 'a' .. 'z', 'A' .. 'Z', '0' .. '9', '_', '.', '-' ],
    deny                => ALL,
    allow               => [ (
                                SSH2_FXP_OPEN,
                                SSH2_FXP_CLOSE,
                                SSH2_FXP_READ,
                                SSH2_FXP_WRITE,
                                SSH2_FXP_LSTAT,
                                SSH2_FXP_STAT_VERSION_0,
                                SSH2_FXP_FSTAT,
                                SSH2_FXP_OPENDIR,
                                SSH2_FXP_READDIR,
                                SSH2_FXP_REMOVE,
                                SSH2_FXP_STAT,
                                SSH2_FXP_RENAME,
                             )],
    fake_ok             => [ (
                                SSH2_FXP_SETSTAT,
                                SSH2_FXP_FSETSTAT,
                             )],
  );

  $sftp->run();

  sub ActionOnSent {
    my $filename = shift;
     ## Do Stuff
  }

  sub ActionOnReceived {
    my $filename = shift;
     ## Do Stuff
  }

=head1 DEPENDENCIES

  Stat::lsMode
  Fcntl
  POSIX
  Sys::Syslog
  Errno

=head1 SEE ALSO

Sftp protocol L<http://www.openssh.org/txt/draft-ietf-secsh-filexfer-02.txt>

=head1 AUTHOR

  Simon Day, Pirum Systems Ltd
  cpan <at> simonday.info

=head1 COPYRIGHT AND LICENSE


Based on sftp-server.c
Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.

Ported to Perl and extended by Simon Day
Copyright (c) 2009 Pirum Systems Ltd.  All rights reserved.

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


=cut

