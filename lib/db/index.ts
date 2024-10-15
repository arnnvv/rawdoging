import { Pool } from "@neondatabase/serverless";

class DBPool {
	private static instace: DBPool;
	private pool: Pool;
	private constructor() {
		const connectionString: string = this.getConnectionString();
		this.pool = new Pool({ connectionString });
		this.pool.on("error", (err) => console.error(err));
	}

	public static getInstance(): DBPool {
		if (!this.instace) this.instace = new DBPool();

		return this.instace;
	}

	private getConnectionString(): string {
		const connectionString: string =
			process.env.DATABASE_URL! ??
			(() => {
				throw new Error("DB not given");
			})();
		return connectionString;
	}

	public getPool(): Pool {
		return this.pool;
	}
}

export const db: Pool = DBPool.getInstance().getPool();
