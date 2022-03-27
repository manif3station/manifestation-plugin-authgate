package AuthGate::Services;

use Dancer2 appname => 'Web';

use MF::Utils qw( load_yaml defor );

hook before_template_render => {
    AuthGate => sub {
        my ($stash) = @_;
        $stash->{user} = sub {
            my $username = AuthGate::Service->session->{username}
              or return redirect '/login';
            return AuthGate::Service->user( username => $username );
        };
    },
};

sub init {
    {
        user => {
            class        => 'AuthGate::User',
            dependencies => [
                qw(
                  users
                  )
            ],
            parameters => {
                username => { isa => 'Str', required => 1 },
            }
        },
        users => {
            block => sub {
                my $users = load_yaml( $ENV{MF_USERS_RECORD} );
                my $roles = load_yaml( $ENV{MF_ROLES_RECORD} );

                foreach my $user ( keys $users->%* ) {
                    foreach my $role ( keys $users->{$user}{roles}->%* ) {
                        foreach my $area ( keys $roles->{$role}{can}->%* ) {
                            foreach my $action (
                                keys $roles->{$role}{can}{$area}->%* )
                            {
                                $users->{$user}{can}{$area}{$action} //=
                                  $roles->{$role}{can}{$area}{$action};
                            }
                        }
                    }
                }

                return $users;
            },
        },
        session => {
            block => sub { defor session('data'), session( 'data', {} ) }
        },
        delete_session => {
            block => sub { session( data => {} ) },
        },
        authcheck => {
            block => sub {
                my $srv = shift;

                my $session = $srv->param('session');

                my $username = $session->{username};

                if ( !$username ) {
                    my $path = request->path_info;

                    $session->{redirect_to} = $path
                      if $path ne '/login';

                    return redirect '/login';
                }

                my $roles = $srv->param('roles');
                my $user =
                  $srv->param('user')->inflate( username => $username );

                return pass
                  if !$roles || $user->has_roles($roles);

                status 403;

                return redirect '/login';
            },
            dependencies => [qw(session user)],
            parameters   => {
                roles => { isa => 'ArrayRef|Str', required => 0 }
            },
        },
    };
}

1;
