package Routes::AuthGate;

use Dancer2 appname => 'Web';

use MF::Services;
use MF::Utils qw(defor);

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

get '/login' => sub {
    template 'AuthGate/login.tt';
};

post '/login' => sub {
    my $username = params->{username}
        or return template 'AuthGate/login.tt';

    my $password = params->{password}
        or redirect '/login';

    my $user = AuthGate::Service->user(username => $username);

    return redirect '/login' if !$user->info;

    my $pass = $user->{password} eq $password
        or return redirect '/login';

    my $session = AuthGate::Service->session;

    $session->{username} = $username;

    my $redirect = defor delete $session->{redirect_to}, '/admin';

    redirect $redirect;
};

any '/logout' => sub {
    AuthGate::Service->delete_session;
    redirect '/login';
};

1;
