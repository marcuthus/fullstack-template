import { NextResponse } from "next/server"
import { z } from "zod"

import { UserRole } from "@/generated/prisma/client"
import { AuthenticatedUser, authMiddleware, handleRouteError } from "@/helpers/auth.helper"
import { signUpSchema } from "@/schemas/users/auth.schema"
import { deleteUser, findUserById, updateUser, verifyUserPassword } from "@/services/user.service"

// Schema for PATCH, all fields optional. Changing your own password requires the current one.
const patchUserSchema = signUpSchema.partial().extend({
    currentPassword: z.string().min(1).optional(),
})

async function checkAccess(auth: { user: AuthenticatedUser }, id: string) {
    if (auth.user.role === UserRole.ADMIN) return true
    if (auth.user.id === id) return true
    return false
}

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
    try {
        const { id } = await params
        const auth = await authMiddleware(request)

        if (auth instanceof NextResponse) return auth

        if (!(await checkAccess(auth, id))) {
            return NextResponse.json({ message: "Forbidden" }, { status: 403 })
        }

        const user = await findUserById(id)

        if (!user) {
            return NextResponse.json({ message: "User not found" }, { status: 404 })
        }

        return NextResponse.json(user)
    } catch (error) {
        return handleRouteError(error)
    }
}

export async function PATCH(request: Request, { params }: { params: Promise<{ id: string }> }) {
    try {
        const { id } = await params
        const auth = await authMiddleware(request)

        if (auth instanceof NextResponse) return auth

        if (!(await checkAccess(auth, id))) {
            return NextResponse.json({ message: "Forbidden" }, { status: 403 })
        }

        const body = await request.json()
        const { currentPassword, ...validatedData } = patchUserSchema.parse(body)

        // Sem isso, um access token vazado bastava para trocar a senha e tomar a conta.
        if (validatedData.password && auth.user.id === id) {
            const isCurrentPasswordValid = await verifyUserPassword(id, currentPassword)

            if (!isCurrentPasswordValid) {
                return NextResponse.json(
                    { message: "Current password is invalid" },
                    { status: 401 }
                )
            }
        }

        const user = await updateUser(id, validatedData)

        return NextResponse.json(user)
    } catch (error) {
        return handleRouteError(error)
    }
}

export async function DELETE(request: Request, { params }: { params: Promise<{ id: string }> }) {
    try {
        const { id } = await params
        const auth = await authMiddleware(request)

        if (auth instanceof NextResponse) return auth

        if (!(await checkAccess(auth, id))) {
            return NextResponse.json({ message: "Forbidden" }, { status: 403 })
        }

        await deleteUser(id)

        return new NextResponse(null, { status: 204 })
    } catch (error) {
        return handleRouteError(error)
    }
}
