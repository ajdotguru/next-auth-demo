import type { NextPage } from 'next';
import { useSession, signIn, signOut } from 'next-auth/react';

const Home: NextPage = () => {
	const { data: session } = useSession();

	console.log('session :: ', session);

	if (session) {
		return (
			<>
				Signed in as {session?.user?.name} <br />
				<button onClick={() => signOut({ redirect: false })}>Sign out</button>
			</>
		);
	}

	return (
		<>
			Not signed in <br />
			<button onClick={() => signIn('github')}>Sign in</button>
		</>
	);
};

export default Home;
