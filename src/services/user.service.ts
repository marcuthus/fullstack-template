import crypto from "node:crypto"

import { Prisma, UserRole } from "@/generated/prisma/client"
import { HttpError } from "@/helpers/auth.helper"
import { prisma } from "@/helpers/prisma.helper"
import { SignUpValues } from "@/schemas/users/auth.schema"
import { comparePassword, hashPassword } from "@/utils/password.util"

export async function findUserById(id: string) {
    const user = await prisma.user.findUnique({
        where: { id },
    })

    if (!user) return null

    const { password: _, ...userWithoutPassword } = user
    return userWithoutPassword
}

export async function findAllUsers() {
    const users = await prisma.user.findMany({
        orderBy: { createdAt: "desc" },
    })

    return users.map(({ password: _, ...u }) => u)
}

export async function createUser(data: SignUpValues) {
    const existingUser = await prisma.user.findFirst({
        where: {
            OR: [{ email: data.email }, { username: data.username }],
        },
    })

    if (existingUser) {
        throw new HttpError(409, "User or email already registered")
    }

    const hashedPassword = await hashPassword(data.password)
    const apiKey = `user_${crypto.randomBytes(16).toString("hex")}`

    const user = await prisma.user.create({
        data: {
            ...data,
            password: hashedPassword,
            apiKey,
            role: UserRole.USER,
        },
    })

    const { password: _, ...userWithoutPassword } = user
    return userWithoutPassword
}

export async function updateUser(id: string, data: Partial<SignUpValues> & { role?: UserRole }) {
    const updateData: Prisma.UserUpdateInput = { ...data }

    if (data.password) {
        updateData.password = await hashPassword(data.password)
    }

    const user = await prisma.user.update({
        where: { id },
        data: updateData,
    })

    const { password: _, ...userWithoutPassword } = user
    return userWithoutPassword
}

export async function verifyUserPassword(id: string, password: string | undefined) {
    if (!password) return false

    const user = await prisma.user.findUnique({
        where: { id },
        select: { password: true },
    })

    if (!user) return false

    return await comparePassword(password, user.password)
}

export async function deleteUser(id: string) {
    await prisma.user.delete({
        where: { id },
    })
    return true
}
