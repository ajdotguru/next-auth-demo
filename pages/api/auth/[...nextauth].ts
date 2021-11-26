// @ts-nocheck
import NextAuth from 'next-auth';
import GithubProvider from 'next-auth/providers/github';
import jwt from 'jsonwebtoken';

export default NextAuth({
	providers: [
		GithubProvider({
			clientId: process.env.GITHUB_ID,
			clientSecret: process.env.GITHUB_SECRET,
		}),
	],
	secret: process.env.SECRET,
	jwt: {
		secret: process.env.SECRET,
		encode: async ({ secret, token }) => {
			const jwtClaims = {
				sub: token.id,
				name: token.name,
				// picture: token.picture,
				iat: Date.now() / 1000,
				exp: Math.floor(Date.now() / 1000) + 60 * 60,
				'https://hasura.io/jwt/claims': {
					'x-hasura-allowed-roles': ['user'],
					'x-hasura-default-role': 'user',
					'x-hasura-role': 'user',
					'x-hasura-user-id': token.id,
				},
			};

			const encodedToken = jwt.sign(jwtClaims, secret, { algorithm: 'HS256' });

			return encodedToken;
		},
		decode: async ({ secret, token }) => {
			const decodedToken = jwt.verify(token, secret, { algorithms: ['HS256'] });

			return decodedToken;
		},
	},
	callbacks: {
		async session({ session, token }) {
			const encodedToken = jwt.sign(token, process.env.SECRET, {
				algorithm: 'HS256',
			});

			session.id = token.id;
			session.token = encodedToken;

			return Promise.resolve(session);
		},
		async jwt({ token, user, account, profile, isNewUser }) {
			if (user) {
				token.id = user.id;
			}

			return Promise.resolve(token);
		},
		redirect({ url, baseUrl }) {
			if (url.startsWith(baseUrl)) return url;
			else if (url.startsWith('/')) return new URL(url, baseUrl).toString();
			return baseUrl;
		},
	},
	debug: true,
});
