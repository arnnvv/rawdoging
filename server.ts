import { ApolloServer, gql } from "apollo-server";
import { db } from "./lib/db";

let books = [
	{ title: "Chut ki rani", author: "Lauda" },
	{ title: "Laudo ka raja", author: "Bada Lauda" },
];

(async () => {
	const server = new ApolloServer({
		typeDefs: gql`
  type Book {
    title: String
    author: String
  }

  input NewBookInput {
        title: String!
        author: String!
  }

  type Query {
    books: [Book]
  }

  type Mutation {
        addBook(input: NewBookInput): Book
  }
`,
		resolvers: {
			Query: {
				books: async () =>
					(await db.query("SELECT title, author FROM books")).rows,
			},
			Mutation: {
				addBook: async (_parent, { input }) => {
					const { title, author } = input;
					const res = await db.query(
						"INSERT INTO books (title, author) VALUES ($1, $2) RETURNING title, author",
						[title, author],
					);
					return res.rows[0];
				},
			},
		},
	});

	const { url } = await server.listen();
	console.log(`Server listning on ${url}`);
})();
