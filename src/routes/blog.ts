import { PrismaClient } from "@prisma/client/edge";
import { withAccelerate } from "@prisma/extension-accelerate";
import { Hono } from "hono";
import { sign, verify } from "hono/jwt";

// Define a custom context with 'userId'
interface CustomContext {
  Bindings: {
    DATABASE_URL: string;
    JWT_SECRET: string;
  };
  Variables: {
    userId: string; // Include userId in the context variables
  };
}


export const blogRouter = new Hono<CustomContext>();
// Middleware to verify JWT token in headers
blogRouter.use('/*', async (c, next) => {
  const authHeader = c.req.header('Authorization'); // Get the Authorization header

  if (!authHeader) {
    return c.text('Authorization header missing', 403); // Return 403 if header is missing
  }

  const token = authHeader.split(' ')[1]; // Assume the header is in the form: 'Bearer <token>'

  if (!token) {
    return c.text('Token missing from Authorization header', 403); // Return 403 if token is missing
  }

  try {
    // Verify the token using the secret from environment variables
    const decoded = await verify(token, c.env.JWT_SECRET)  // Use JWT_SECRET from your environment
    if (!decoded||!decoded.id) {
      c.status(401);
      return c.json({ error: "unauthorized" });
    }
    c.set('userId', decoded.id);
    // Proceed to the next middleware/handler
    await next();
  } catch (error) {
    return c.text('Invalid or expired token', 403); // Return 403 if token is invalid or expired
  }
});

blogRouter.post('/', async (c) => {
  const prisma = new PrismaClient({
		datasourceUrl: c.env?.DATABASE_URL	,
	}).$extends(withAccelerate());
  const body = await c.req.json();
  const userId = c.get("userId");
  try {
	const post = await prisma.post.create({
		data : {
		  title : body.title,
		  content : body.content,
		  authorId:Number(userId)
		}
	  });
	  return c.json({
		id:post.id
	  });
  } catch (error:any) {
	 console.error(error);
    return c.text('Error creating post: ' + error.message, 500);
  } finally {
    await prisma.$disconnect(); // Ensure the connection is closed
  }
});

blogRouter.put('/', async (c) => {
	const userId = c.get('userId');
	const prisma = new PrismaClient({
		datasourceUrl: c.env?.DATABASE_URL	,
	}).$extends(withAccelerate());

	const body = await c.req.json();
	const blog = await prisma.post.update({
		where: {
			id: body.id,
			authorId: Number(userId)
		},
		data: {
			title: body.title,
			content: body.content
		}
	});

	return c.json({
        id: blog.id
    })
});
blogRouter.get('/bulk', async (c) => {
	const prisma = new PrismaClient({
		datasourceUrl: c.env?.DATABASE_URL	,
	}).$extends(withAccelerate());
	
	const posts = await prisma.post.findMany({});

	return c.json({posts});
})
blogRouter.get('/:id', async (c) => {
	const id = c.req.param("id");
	const prisma = new PrismaClient({
		datasourceUrl: c.env?.DATABASE_URL	,
	}).$extends(withAccelerate());
	
	const post = await prisma.post.findFirst({
		where: {
			id:Number(id)
		}
	});

	return c.json({post});
})


export default blogRouter;
