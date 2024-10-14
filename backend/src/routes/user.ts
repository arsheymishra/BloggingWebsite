import { PrismaClient } from "@prisma/client/edge";
import { withAccelerate } from "@prisma/extension-accelerate";
import { Hono } from "hono";
import { sign } from "hono/jwt";

export const userRouter = new Hono<{
    Bindings: {
        DATABASE_URL: string;
        JWT_SECRET: string;
    }
}>();

// Hashing function using Web Crypto API
async function hashPassword(password: string | undefined) {
    if (!password) throw new Error('Password is required'); // Handle undefined passwords
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  
  // Function to generate JWT
 async function generateToken(userId: string, jwtSecret: string) {
    return await sign({ id: userId }, jwtSecret); // Set expiration time as needed
  }
  
  userRouter.post('/signup', async (c) => {
    try {
      const { name, email, password } = await c.req.json();
      
      // Use the DATABASE_URL from the environment variables
      const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
      }).$extends(withAccelerate());
  
      // Hash the password using the Web Crypto API
      const hashedPassword = await hashPassword(password);
  
      // Store the user with the hashed password
      const newUser = await prisma.user.create({
        data: {
          name,
          email,
          password: hashedPassword,
        },
      });
  
      // Generate a JWT token for the new user
      const token = await generateToken(newUser.id, c.env.JWT_SECRET); // Use JWT_SECRET from environment variables
  
      // Return the user ID and token
      return c.json({ userId: newUser.id, token });
    } catch (error:any) {
      console.error(error);
      return c.text('Error creating user: ' + error.message, 500);
    }
  });

  userRouter.post('/signin', async (c) => {
    try {
      const { email, password } = await c.req.json();
  
      // Use the DATABASE_URL from environment variables
      const prisma = new PrismaClient({
        datasourceUrl: c.env.DATABASE_URL,
      }).$extends(withAccelerate());
  
      // Fetch user by email
      const user = await prisma.user.findUnique({
        where: { email },
      });
  
      if (!user) {
        return c.text('User not found', 404); // Return 404 if user doesn't exist
      }
  
      // Compare the provided password with the hashed password
      const hashedPassword = await hashPassword(password);
      if (hashedPassword !== user.password) {
        return c.text('Invalid credentials', 401); // Return 401 if password is incorrect
      }
  
      // Generate a JWT for the user
      const token = await generateToken(user.id, c.env.JWT_SECRET);
  
      // Return the token and user info
      return c.json({ userId: user.id, token });
    } catch (error : any) {
      console.error(error);
      return c.text('Error signing in: ' + error.message, 500);
    }
  });