import { NextResponse } from "next/server"

import { handleRouteError } from "@/helpers/auth.helper"
import { signUpSchema } from "@/schemas/users/auth.schema"
import { signUp } from "@/services/auth.service"

export async function POST(request: Request) {
    try {
        const body = await request.json()
        const validatedData = signUpSchema.parse(body)

        const user = await signUp(validatedData)

        return NextResponse.json(user, { status: 201 })
    } catch (error) {
        return handleRouteError(error)
    }
}
