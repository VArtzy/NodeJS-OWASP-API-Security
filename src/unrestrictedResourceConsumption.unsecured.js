import express from 'express'
import { graphqlHTTP } from 'express-graphql'
import rateLimit from 'express-rate-limit'
import { buildSchema } from 'graphql'
import sharp from 'sharp'

const app = express()

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
})

app.use(apiLimiter)

const processThumbnail = async (base64Image) => {
    if (base64Image > 1000000) throw new Error('Image is too large')

    const buff = Buffer.from(base64Image, 'base64')
    await sharp(buff).resize(200, 200).toBuffer()
    return 'http://example.com/thumbnail.jpg'
}

const schema = buildSchema(`
    type Mutation {
        uploadPic(name: String!, base64Pic: String!): PicUploadResult
    }

    type PicUploadResult {
        url: String
    }

    type Query {
        dummy: String
    }
`)

const root = {
    uploadPic: async ({ base64Pic }) => {
        const url = await processThumbnail(base64Pic)
        return { url }
    },
    dummy: () => 'dummy'
}

// Graphql endpoint with batch request vulnerability
app.use('/graphql', graphqlHTTP({
    schema,
    rootValue: root,
    graphiql: true
}))

app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
