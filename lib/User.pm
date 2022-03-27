package AuthGate::User;

use Moo;

has users    => ( is => 'ro', required => 1 );
has username => ( is => 'ro', required => 1 );
has password => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        my ($self) = @_;
        $self->info->{password};
    }
);

has info => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        my ($self) = @_;
        $self->users->{ $self->username };
    }
);

sub can_do {
    my ( $self, $ability ) = @_;
    my ( $action, $area ) = split /\./, $ability;
    my $can = $self->info->{can};
    return $can->{anything}
      || $can->{$area}{$action};
}

sub has_role {
    my ( $self, $roles ) = @_;
    return 1 if !$roles;
    $roles = [$roles] if !UNIVERSAL::isa( $roles, 'ARRAY' );
    my $user_roles = $self->info->{roles};
    return 1 if $user_roles->{anything};
    foreach my $role (@$roles) {
        return 1 if $user_roles->{$role};
    }
    return 0;
}

1;
