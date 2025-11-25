import { hash, compare } from 'bcryptjs'
import type { NextAuthOptions, DefaultSession } from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'
import prisma from '@/lib/prisma'

declare module 'next-auth' {
  interface Session extends DefaultSession {
    user: {
      id: string
      email: string
      name: string
      role: 'hr' | 'manager'
    } & DefaultSession['user']
  }

  interface User {
    id: string
    email: string
    name: string
    role: 'hr' | 'manager'
  }

  interface JWT {
    id: string
    email: string
    name: string
    role: 'hr' | 'manager'
  }
}

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: {
          label: 'Email',
          type: 'text',
          placeholder: 'user@example.com',
        },
        password: {
          label: 'Password',
          type: 'password',
        },
      },
      async authorize(
        credentials: Record<'email' | 'password', string> | undefined
      ): Promise<{
        id: string
        email: string
        name: string
        role: 'hr' | 'manager'
      } | null> {
        if (!credentials?.email || !credentials?.password) {
          throw new Error('Invalid credentials')
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
        })

        if (!user) {
          throw new Error('User not found')
        }

        const isPasswordValid = await compare(
          credentials.password,
          user.password
        )

        if (!isPasswordValid) {
          throw new Error('Invalid password')
        }

        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role as 'hr' | 'manager',
        }
      },
    }),
  ],
  pages: {
    signIn: '/auth/login',
    error: '/auth/login',
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id
        token.email = user.email
        token.name = user.name
        token.role = user.role
      }
      return token
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id as string
        session.user.email = token.email as string
        session.user.name = token.name as string
        session.user.role = token.role as 'hr' | 'manager'
      }
      return session
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60,
    updateAge: 24 * 60 * 60,
  },
  jwt: {
    secret: process.env.NEXTAUTH_SECRET,
    maxAge: 30 * 24 * 60 * 60,
  },
  events: {
    async signIn({ user, isNewUser }) {
      console.log(`User ${user.email} signed in`)
    },
    async signOut({ token }) {
      console.log(`User signed out`)
    },
  },
}